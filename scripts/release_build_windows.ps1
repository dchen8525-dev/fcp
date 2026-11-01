# Windows 发布构建：configure → build → ctest → windeployqt → 启动冒烟 → Inno Setup。
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
# 产出：dist\FCP-Client-<version>-win64-setup.exe
# 基础镜像里 Inno Setup 6 已预装；没有的话脚本会尝试 choco。

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

# --- windeployqt：部署目录 = 装完后的程序目录 ---------------------------------
# 产物位置随生成器不同（Ninja 在 apps\fcp-client\，VS multi-config 在
# apps\fcp-client\Release\），直接找，不把生成器细节写死在这里。
$exe = (Get-ChildItem -Path $BuildDir -Recurse -Filter fcp_client.exe |
        Select-Object -First 1).FullName
if (!$exe) { throw "fcp_client.exe 没产出（在 $BuildDir 下找不到）" }
New-Item -ItemType Directory -Force (Join-Path $dist "deploy") | Out-Null
Copy-Item $exe (Join-Path $dist "deploy")
$deploy = Join-Path $dist "deploy"
& (Join-Path $QtRoot "bin\windeployqt.exe") --release --no-translations `
    --compiler-runtime --dir $deploy (Join-Path $deploy "fcp_client.exe")
if ($LASTEXITCODE -ne 0) { throw "windeployqt 失败（exit $LASTEXITCODE）" }

# 运行时最小集：少一个 = 装完启动即报缺 DLL（部署目录不做兜底，这里就必须咬住）。
$required = @("fcp_client.exe", "Qt6Core.dll", "Qt6Gui.dll", "Qt6Widgets.dll",
              "Qt6Network.dll", "platforms\qwindows.dll")
foreach ($f in $required) {
  if (!(Test-Path (Join-Path $deploy $f))) { throw "部署目录缺 $f" }
}

# --- 启动冒烟：部署目录里的 exe 必须活过 6 秒 ---------------------------------
Write-Host "== 启动冒烟"
$p = Start-Process -FilePath (Join-Path $deploy "fcp_client.exe") -PassThru
Start-Sleep -Seconds 6
if ($p.HasExited) {
  throw "fcp_client.exe 启动即退出（exit $($p.ExitCode)）—— 多半是缺 DLL"
}
Stop-Process -Id $p.Id -Force

# --- Inno Setup ---------------------------------------------------------------
$iscc = "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe"
if (!(Test-Path $iscc)) {
  choco install innosetup --no-progress -y
  $iscc = "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe"
}
if (!(Test-Path $iscc)) { throw "找不到 ISCC.exe" }

& $iscc "/DMyAppVersion=$Version" `
        "/DSourceDir=$deploy" `
        "/DOutputDir=$dist" `
        "/DDocsDir=$(Join-Path $repo 'docs')" `
        (Join-Path $repo "packaging\windows\fcp-client.iss")
if ($LASTEXITCODE -ne 0) { throw "ISCC 失败（exit $LASTEXITCODE）" }

Get-ChildItem (Join-Path $dist "*.exe") |
  Where-Object { $_.Name -notlike "fcp_client*" } |
  Format-Table Name, Length
