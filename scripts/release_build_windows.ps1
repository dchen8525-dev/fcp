# Windows 发布构建：configure → build → ctest → windeployqt → 启动冒烟 → 单文件 exe。
#
# 发布工作流（.github/workflows/release.yml 的 windows-client job）的每一步都是
# 这里的一段；本地复现用同一条命令，见 docs/发布流程.md §2。
#
# 用法（在 VS 开发者命令行里，或先 call vcvars64.bat）：
#   pwsh -File scripts/release_build_windows.ps1 `
#     -QtRoot "$env:VCPKG_ROOT\installed\x64-windows\."  # 或 aqtinstall 的 Qt 目录
#
# 参数：
#   -QtRoot       Qt6 的安装前缀（含 lib/cmake/Qt6）；aqtinstall 用 $env:QT_ROOT_DIR
#   -Version      缺省取仓库根 VERSION 文件
#   -BuildDir     缺省 <repo>\build\release-win
#   -SkipTests    只构建不跑 ctest（手工出试装包时用；发布流水线从不跳过）
#
# 产出：dist\FCP-Client-<version>-win64.exe
# 单文件自解压便携版：双击运行，不安装、不写卸载信息、不需要管理员权限。

[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$QtRoot,
  [string]$Version,
  [string]$BuildDir,
  [switch]$SkipTests
)

$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot
if (-not $Version) {
  $Version = (Get-Content (Join-Path $repo "VERSION") -Raw).Trim()
}
if (-not $BuildDir) {
  $BuildDir = Join-Path $repo "build\release-win"
}
$dist = Join-Path $repo "dist"

Write-Host "== fcp $Version release build"
Write-Host "   build : $BuildDir"
Write-Host "   qtroot: $QtRoot"

# 不指定 -G：Windows 上 CMake 默认挑 Visual Studio 生成器（multi-config），
# 这样不需要先把 cl.exe 摆进 PATH（runner 的默认 shell 里没有 vcvars 环境）。
# 显式 -DCMAKE_BUILD_TYPE 只在单配置生成器下生效，multi-config 下由 --config 决定。
cmake -S $repo -B $BuildDir `
  -DCMAKE_BUILD_TYPE=Release `
  -DCMAKE_PREFIX_PATH="$QtRoot" `
  -DFCP_RELEASE_VERSION="$Version" `
  -DFCP_BUILD_APP=ON `
  -DFCP_BUILD_PROXY=ON `
  -DFCP_BUILD_TESTS=ON `
  -DFCP_BUILD_TOOLS=ON
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

cmake --build $BuildDir --config Release --parallel
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

if (-not $SkipTests) {
  Write-Host "== ctest（发布门禁）"
  ctest --test-dir $BuildDir -C Release --output-on-failure
  if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

function Find-VsTool([string]$relativeGlob) {
  $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
  if (!(Test-Path $vswhere)) { return $null }
  $vs = & $vswhere -latest -products * `
        -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
        -property installationPath
  if (!$vs) { return $null }
  $hit = Get-ChildItem (Join-Path $vs $relativeGlob) -ErrorAction SilentlyContinue |
         Sort-Object FullName -Descending | Select-Object -First 1
  if ($hit) { return $hit.FullName }
  return $null
}

# windeployqt 只认识官方 Qt 的布局。vcpkg 的 qtbase 会动态链接 zlib/zstd/
# pcre2/ICU/OpenSSL 等第三方 DLL，windeployqt 不会拷；这里按 PE 导入表递归补齐，
# 否则本地用 vcpkg Qt 出的单文件 exe 会"双击即报缺 DLL"。
function Copy-MissingDllDependencies([string]$dir, [string]$searchDir) {
  $dumpbin = Find-VsTool 'VC\Tools\MSVC\*\bin\Hostx64\x64\dumpbin.exe'
  if (!$dumpbin) {
    Write-Warning "找不到 dumpbin.exe，跳过第三方 DLL 依赖补齐（官方 Qt 不需要）"
    return
  }
  $queue = New-Object System.Collections.Queue
  Get-ChildItem $dir -Recurse -Include *.exe, *.dll | ForEach-Object { $queue.Enqueue($_.FullName) }
  $seen = @{}
  while ($queue.Count -gt 0) {
    $file = [string]$queue.Dequeue()
    if ($seen.ContainsKey($file)) { continue }
    $seen[$file] = $true
    foreach ($line in (& $dumpbin /dependents $file 2>$null)) {
      if ($line -notmatch '^\s+(\S+\.dll)\s*$') { continue }
      $name = $Matches[1]
      if ($name -like 'api-ms-win-*' -or $name -like 'ext-ms-*') { continue }
      $target = Join-Path $dir $name
      if (Test-Path $target) { continue }
      $candidate = Join-Path $searchDir $name
      if (Test-Path $candidate) {
        Copy-Item $candidate $target
        $queue.Enqueue($target)
      } elseif (!(Test-Path (Join-Path $env:SystemRoot "System32\$name"))) {
        Write-Warning "部署目录仍缺 $name（$file 依赖）"
      }
    }
  }
}

# --- windeployqt：部署目录 = 装完后的程序目录 ---------------------------------
# 产物位置随生成器不同（Ninja 在 apps\fcp-client\，VS multi-config 在
# apps\fcp-client\Release\），直接找，不把生成器细节写死在这里。
$exe = (Get-ChildItem -Path $BuildDir -Recurse -Filter fcp_client.exe |
        Select-Object -First 1).FullName
if (!$exe) { throw "fcp_client.exe 没产出（在 $BuildDir 下找不到）" }
$deploy = Join-Path $dist "deploy"
# 每次从空目录开始：否则上一次部署残留的 DLL 会被打进便携包。
if (Test-Path $deploy) { Remove-Item -Recurse -Force $deploy }
New-Item -ItemType Directory -Force $deploy | Out-Null
Copy-Item $exe $deploy

# aqtinstall 的 Qt 把 windeployqt 放在 bin\；vcpkg 的 qtbase 放在
# tools\Qt6\bin\。两种本地环境都支持。
$windeployqt = Join-Path $QtRoot "bin\windeployqt.exe"
if (!(Test-Path $windeployqt)) {
  $windeployqt = Join-Path $QtRoot "tools\Qt6\bin\windeployqt.exe"
}
if (!(Test-Path $windeployqt)) { throw "找不到 windeployqt.exe（QtRoot=$QtRoot）" }
& $windeployqt --release --no-translations --no-compiler-runtime `
    --dir $deploy (Join-Path $deploy "fcp_client.exe")
if ($LASTEXITCODE -ne 0) { throw "windeployqt 失败（exit $LASTEXITCODE）" }

# 便携包不能要求用户先运行 vc_redist 安装器，直接把 app-local CRT 拷进来；
# 官方 Qt 的 windeployqt 在 --compiler-runtime 下放的是安装器而不是 DLL。
$crtDir = Find-VsTool 'VC\Redist\MSVC\*\x64\Microsoft.VC*.CRT'
if ($crtDir) {
  Copy-Item (Join-Path $crtDir '*.dll') $deploy -Force
} else {
  Write-Warning "没找到 VC 运行库目录；便携包依赖系统已安装的 MSVC 运行库"
}
Remove-Item (Join-Path $deploy 'vc_redist.x64.exe') -ErrorAction SilentlyContinue

# vcpkg 版 Qt 的第三方动态依赖（zlib/zstd/pcre2/ICU/OpenSSL）不在
# windeployqt 的清单里；按导入表补齐，官方 Qt 下通常什么也不用加。
Copy-MissingDllDependencies $deploy (Join-Path $QtRoot 'bin')

# 运行时最小集：少一个 = 装完启动即报缺 DLL（部署目录不做兜底，这里就必须咬住）。
$required = @("fcp_client.exe", "Qt6Core.dll", "Qt6Gui.dll", "Qt6Widgets.dll",
              "Qt6Network.dll", "platforms\qwindows.dll")
foreach ($f in $required) {
  if (!(Test-Path (Join-Path $deploy $f))) { throw "部署目录缺 $f" }
}

# --- 启动冒烟：部署目录里的 exe 必须能建窗并干净退出 --------------------------
# --smoke-test 让 GUI 2.5 秒后自行退出；用退出码判断，不依赖杀进程。
Write-Host "== 部署目录冒烟"
$p = Start-Process -FilePath (Join-Path $deploy "fcp_client.exe") `
      -ArgumentList '--smoke-test' -PassThru
if (!$p.WaitForExit(15000)) {
  throw "fcp_client.exe 15 秒内未退出（--smoke-test）—— 多半是缺 DLL"
}
if ($p.ExitCode -ne 0) {
  throw "fcp_client.exe 退出码 $($p.ExitCode)（--smoke-test）"
}

# --- 单文件便携 exe：7zSD 自解压 ----------------------------------------------
# 用户下载一个 .exe，双击即运行：7zSD 把载荷解到临时目录、启动 fcp_client.exe，
# 程序退出后临时目录由 SFX 清理。不写 Program Files、不建卸载项、不写服务；
# 配置仍由 QSettings 存到 HKCU\Software\FCP\FCPClient。
Write-Host "== 单文件便携 exe"
$sevenZip = "${env:ProgramFiles}\7-Zip\7z.exe"
if (!(Test-Path $sevenZip)) {
  $sevenZip = "${env:ProgramFiles(x86)}\7-Zip\7z.exe"
}
if (!(Test-Path $sevenZip)) { throw "找不到 7z.exe（发布镜像应预装 7-Zip）" }

$payload = Join-Path $BuildDir "fcp-client-payload.7z"
if (Test-Path $payload) { Remove-Item $payload }
Push-Location $deploy
& $sevenZip a -t7z -mx=5 $payload . | Out-Null
$sevenZipExit = $LASTEXITCODE
Pop-Location
if ($sevenZipExit -ne 0) { throw "7z 打包失败（exit $sevenZipExit）" }

$config = Join-Path $BuildDir "fcp-client-sfx.txt"
$cfgText = ";!@Install@!UTF-8!`nTitle=`"FCP Client`"`nRunProgram=`"fcp_client.exe`"`n;!@InstallEnd@!`n"
Set-Content -Path $config -Value $cfgText -Encoding ASCII -NoNewline

$sfxModule = Join-Path $repo 'packaging\windows\7zSD.sfx'
if (!(Test-Path $sfxModule)) { throw "缺 $sfxModule" }
$outExe = Join-Path $dist "FCP-Client-$Version-win64.exe"
if (Test-Path $outExe) { Remove-Item $outExe }
$out = [System.IO.File]::Create($outExe)
try {
  foreach ($part in @($sfxModule, $config, $payload)) {
    $in = [System.IO.File]::OpenRead($part)
    try { $in.CopyTo($out) } finally { $in.Dispose() }
  }
} finally {
  $out.Dispose()
}
Remove-Item $payload, $config -Force

Write-Host "== 单文件冒烟（--smoke-test）"
$p = Start-Process -FilePath $outExe -ArgumentList '--smoke-test' -PassThru
if (!$p.WaitForExit(30000)) {
  throw "单文件客户端 30 秒内未退出（--smoke-test）"
}
if ($p.ExitCode -ne 0) {
  throw "单文件客户端退出码 $($p.ExitCode)（--smoke-test）"
}

Get-Item $outExe | Format-List Name, Length
