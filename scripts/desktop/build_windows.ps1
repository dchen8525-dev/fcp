# Windows 一键构建：CMake 出 fcp-client → CMake 出 Qt GUI → windeployqt 收集
# Qt 运行库 → 单文件引导器封装。
#
# 用法（在装好 Qt 6 + MSVC 的环境里）：
#   pwsh -File scripts/desktop/build_windows.ps1 `
#     -ProxyBin build\release-win\apps\cli\Release\fcp-client.exe `
#     -QtPrefix D:\work\vcpkg\installed\x64-windows
#
# 参数：
#   -ProxyBin   已构建的 fcp-client.exe（缺省按常见构建目录自动找）
#   -QtPrefix   Qt 6 安装前缀（含 lib\cmake\Qt6 与 bin\windeployqt.exe）；
#               缺省依次尝试 $env:QT_ROOT、$env:VCPKG_ROOT\installed\x64-windows
#   -BuildDir   GUI 的 CMake 构建目录（缺省 build\gui-win）
#   -StageDir   运行库与 sidecar 的收集目录（缺省 build\gui-stage）

[CmdletBinding()]
param(
  [string]$ProxyBin,
  [string]$QtPrefix,
  [string]$BuildDir,
  [string]$StageDir
)

$ErrorActionPreference = "Stop"
$repo = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$guiDir = Join-Path $repo "apps\desktop"
if (-not $BuildDir) { $BuildDir = Join-Path $repo "build\gui-win" }
if (-not $StageDir) { $StageDir = Join-Path $repo "build\gui-stage" }

if (-not $ProxyBin) {
  # Release only. A Debug sidecar needs the Debug CRT (VCRUNTIME140D.dll /
  # ucrtbased.dll), which this script never collects, and it prints the same
  # --version as Release, so the packaging smoke test cannot catch it. Listing
  # the Debug path as a candidate shipped a GUI whose sidecar silently failed to
  # start (M-05).
  $candidates = @(
    (Join-Path $repo "build\release-win\apps\cli\Release\fcp-client.exe"),
    (Join-Path $repo "build\proxy-check\apps\cli\Release\fcp-client.exe"),
    (Join-Path $repo "build\windows-x64\apps\cli\Release\fcp-client.exe")
  )
  $ProxyBin = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
  if (-not $ProxyBin) {
    throw "找不到 Release 的 fcp-client.exe；用 -ProxyBin 指定，或先构建 FCP_BUILD_PROXY=ON（Configuration=Release）"
  }
}
$ProxyBin = (Resolve-Path $ProxyBin).Path
if ($ProxyBin -match '\\Debug\\') {
  throw "-ProxyBin 指向 Debug 产物（$ProxyBin）：Debug sidecar 缺 Debug CRT，不能打进发布物"
}
Write-Host "== sidecar: $ProxyBin"

# The sidecar must report the version this repo is publishing. A stale binary
# left over from an older build has the same file name and would otherwise ship
# with a --version that never gets compared (M-05).
$expectedVersion = (Get-Content (Join-Path $repo "VERSION") -Raw).Trim()
$reported = (& $ProxyBin --version | Out-String).Trim()
if ($LASTEXITCODE -ne 0) {
  throw "sidecar --version 退出码 $LASTEXITCODE（$ProxyBin）"
}
if ($reported -notmatch "fcp-client\s+$([regex]::Escape($expectedVersion))") {
  throw "sidecar 版本不符：报告 '$reported'，期望 fcp-client $expectedVersion（先重建 Release sidecar）"
}
Write-Host "== sidecar version: $expectedVersion"

# --- Qt 6 -------------------------------------------------------------------
if (-not $QtPrefix) {
  $candidates = @()
  if ($env:QT_ROOT) { $candidates += $env:QT_ROOT }
  if ($env:VCPKG_ROOT) { $candidates += (Join-Path $env:VCPKG_ROOT "installed\x64-windows") }
  $QtPrefix = $candidates |
    Where-Object { Test-Path (Join-Path $_ "lib\cmake\Qt6\Qt6Config.cmake") } |
    Select-Object -First 1
  if (-not $QtPrefix) {
    throw "找不到 Qt 6；用 -QtPrefix 指定，或设置 QT_ROOT（需要 lib\cmake\Qt6\Qt6Config.cmake）"
  }
}
$QtPrefix = (Resolve-Path $QtPrefix).Path
Write-Host "== Qt: $QtPrefix"

$windeployqt = @(
  (Join-Path $QtPrefix "tools\Qt6\bin\windeployqt.exe"),
  (Join-Path $QtPrefix "bin\windeployqt.exe")
) | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $windeployqt) { throw "$QtPrefix 下找不到 windeployqt.exe" }

# --- GUI --------------------------------------------------------------------
Write-Host "== CMake: Qt GUI"
cmake -S $guiDir -B $BuildDir -DCMAKE_PREFIX_PATH="$QtPrefix"
if ($LASTEXITCODE -ne 0) { throw "GUI configure 失败" }
cmake --build $BuildDir --config Release --parallel
if ($LASTEXITCODE -ne 0) { throw "GUI build 失败" }

$gui = @(
  (Join-Path $BuildDir "Release\FCP.exe"),   # Visual Studio / multi-config
  (Join-Path $BuildDir "FCP.exe")            # Ninja / single-config
) | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $gui) { throw "找不到构建出来的 FCP.exe（$BuildDir）" }

# --- 收集运行库 --------------------------------------------------------------
Write-Host "== stage: $StageDir"
if (Test-Path $StageDir) { Remove-Item -Recurse -Force $StageDir }
New-Item -ItemType Directory -Force -Path $StageDir | Out-Null
Copy-Item $gui (Join-Path $StageDir "FCP.exe")
Copy-Item $ProxyBin (Join-Path $StageDir "fcp-client.exe")

# windeployqt 自己也要能加载 Qt6Core.dll（vcpkg 的副本在 bin 下）。
$env:PATH = (Join-Path $QtPrefix "bin") + ";" + $env:PATH
# Widgets 走 raster；不要 OpenGL 软件渲染和 D3D 编译器（省 ~25 MiB）。
# MSVC 运行库不用 vc_redist 安装包（18 MiB），直接拷 CRT DLL（~2 MiB）。
& $windeployqt --release --no-translations --no-opengl-sw --no-system-d3d-compiler `
  --no-compiler-runtime --dir $StageDir (Join-Path $StageDir "FCP.exe")
if ($LASTEXITCODE -ne 0) { throw "windeployqt 失败" }

# Qt Quick/RHI 的 D3D12 着色器编译器对 Widgets 无用。
foreach ($unused in @("dxcompiler.dll", "dxil.dll", "vc_redist.x64.exe")) {
  $path = Join-Path $StageDir $unused
  if (Test-Path $path) { Remove-Item -Force $path }
}

# GUI 只链接 Qt6Widgets/Gui/Core（FCP.exe 的导入表里没有 Qt6Network），
# windeployqt 仍会按默认清单带上 Network 与全部图片插件：
#   * tls/、networkinformation/ 依赖 Qt6Network，应用不用网络也不做 TLS；
#   * generic/ 只有 TUIO 触摸输入插件，它反过来 import Qt6Network，是
#     Qt6Network 留在载荷里的唯一原因；
#   * PNG 解码内建于 Qt6Gui，.ico 编在 PE 资源里，imageformats 全不需要。
# 必须在下面的依赖递归之前删：否则 dumpbin 会把 qjpeg/Qt6Network 的
# jpeg62/libcrypto 也补进载荷。
foreach ($dir in @("tls", "networkinformation", "imageformats", "generic")) {
  $path = Join-Path $StageDir $dir
  if (Test-Path $path) { Remove-Item -Recurse -Force $path }
}
$network = Join-Path $StageDir "Qt6Network.dll"
if (Test-Path $network) { Remove-Item -Force $network }

# Visual Studio 路径：dumpbin 与 CRT 都用得上。vcvars 下未必在 PATH，用 vswhere 找。
$vsdir = $null
$vswhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
if (Test-Path $vswhere) {
  $vsdir = & $vswhere -latest -products * `
    -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath |
    Select-Object -First 1
}

# 拷 MSVC CRT：vcvars 会设置 VCToolsRedistDir；CI 里没跑 vcvars 时从 VS 目录找。
$redistRoot = $env:VCToolsRedistDir
if (-not $redistRoot -and $vsdir) {
  $versions = Get-ChildItem (Join-Path $vsdir "VC\Redist\MSVC") -Directory -ErrorAction SilentlyContinue |
    Sort-Object Name -Descending
  if ($versions) { $redistRoot = $versions[0].FullName }
}
$crt = $null
if ($redistRoot) {
  # 同一个 VS 下常有多个 CRT 版本目录（14.2x/14.3x/14.4x），倒序取最新，
  # 否则按字母序会拿到最旧的那份。
  $crt = Get-ChildItem (Join-Path $redistRoot "x64") -Directory -Filter "Microsoft.VC*.CRT" `
    -ErrorAction SilentlyContinue | Sort-Object Name -Descending | Select-Object -First 1
}
if ($crt) {
  Copy-Item (Join-Path $crt.FullName "*.dll") $StageDir
  Write-Host "== MSVC CRT: $($crt.FullName)"
} else {
  Write-Warning "找不到 MSVC CRT DLL；目标机需要预装 Visual C++ 运行库"
}

# vcpkg 构建的 Qt 还依赖 zlib/zstd/pcre2/double-conversion 等第三方 DLL，
# windeployqt 不认识它们。按 PE 依赖递归补齐：只从 $QtPrefix\bin 取，
# 系统 DLL 不拷。
$dumpbin = (Get-Command dumpbin.exe -ErrorAction SilentlyContinue |
  Select-Object -First 1).Source
if (-not $dumpbin -and $vsdir) {
  $dumpbin = Get-ChildItem (Join-Path $vsdir "VC\Tools\MSVC") -Directory |
    Sort-Object Name -Descending |
    ForEach-Object { Join-Path $_.FullName "bin\Hostx64\x64\dumpbin.exe" } |
    Where-Object { Test-Path $_ } | Select-Object -First 1
}
if (-not $dumpbin) {
  Write-Warning "找不到 dumpbin；Qt 的第三方依赖可能没拷全"
} else {
  $queue = New-Object System.Collections.Queue
  # 递归：Qt 插件在 platforms/、styles/、imageformats/ 等子目录里，
  # 它们的第三方依赖同样不在 windeployqt 的清单里。
  Get-ChildItem $StageDir -Recurse -File |
    Where-Object { $_.Extension -in @(".exe", ".dll") } |
    ForEach-Object { $queue.Enqueue($_.FullName) }
  $extra = @{}
  while ($queue.Count -gt 0) {
    $file = $queue.Dequeue()
    foreach ($line in (& $dumpbin /nologo /dependents $file 2>$null)) {
      if ($line -notmatch '^\s+([A-Za-z0-9_.+\-]+\.dll)\s*$') { continue }
      $name = $matches[1]
      $dest = Join-Path $StageDir $name
      if (Test-Path $dest) { continue }
      $src = Join-Path $QtPrefix "bin\$name"
      if (Test-Path $src) {
        Copy-Item $src $dest
        $queue.Enqueue($dest)
        $extra[$name] = $true
      }
    }
  }
  if ($extra.Count -gt 0) {
    Write-Host "== 补充依赖: $($extra.Keys -join ', ')"
  }
}

Write-Host "== 引导器封装"
& (Join-Path $PSScriptRoot "bundle_windows_portable.ps1") -PayloadDir $StageDir
if ($LASTEXITCODE -ne 0) { throw "单文件封装失败" }
