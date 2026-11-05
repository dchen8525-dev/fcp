# 把 Qt 客户端（FCP.exe + fcp-client.exe + Qt 运行库）打成单文件便携 exe。
#
# 安装器（NSIS/MSI）不是这里的目标；要的是"双击即用、删除即卸载"。
# 做法是一个很小的 C++ 引导器（apps/desktop/launcher-cpp，独立 CMake 工程，
# 静态 CRT 零依赖；彻底无 Rust，决策 #75）：
#
#   [fcp-launcher.exe][payload.zip][64 字节尾部]
#
# 首次运行时引导器把载荷（整个目录树，含 platforms/ 等 Qt 插件）解到
# %LOCALAPPDATA%\FCP\bin\<SHA-256 前 8 字节>\，之后直接启动缓存里的 FCP.exe；
# 换新版本按内容哈希分目录，旧目录 7 天未用自动清理。用户配置在注册表
# （QSettings：HKCU\Software\FCP\FCP Client），与这个缓存目录无关，升级不丢。
#
# 用法：
#   pwsh -File scripts/desktop/bundle_windows_portable.ps1 `
#     -PayloadDir build\gui-stage [-Version 0.0.1] [-OutDir dist]

[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$PayloadDir,
  [string]$Version,
  [string]$OutDir
)

$ErrorActionPreference = "Stop"
$repo = Resolve-Path (Join-Path $PSScriptRoot "..\..")
if (-not $Version) {
  $Version = (Get-Content (Join-Path $repo "VERSION") -Raw).Trim()
}
if (-not $OutDir) { $OutDir = Join-Path $repo "dist" }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$PayloadDir = (Resolve-Path $PayloadDir).Path
$app = Join-Path $PayloadDir "FCP.exe"
if (!(Test-Path $app)) { throw "找不到 $app；先运行 build_windows.ps1" }
if (!(Test-Path (Join-Path $PayloadDir "fcp-client.exe"))) {
  throw "载荷里没有 fcp-client.exe；先运行 build_windows.ps1"
}
# 排障时确认缓存目录对应哪个版本。
Set-Content -Path (Join-Path $PayloadDir "version.txt") -Encoding utf8 -Value "FCP $Version"

if (-not [BitConverter]::IsLittleEndian) {
  throw "这个脚本假定小端主机（引导尾部的整数按小端写入）"
}

$stage = Join-Path ([System.IO.Path]::GetTempPath()) ("fcp-launcher-stage-" + [guid]::NewGuid())
New-Item -ItemType Directory -Force -Path $stage | Out-Null
try {
  # 1) 编译引导器（launcher-cpp 独立 CMake 工程；MSVC 默认生成器，
  #    版本号经 APP_VERSION 写进 VERSIONINFO）。
  #    注意：`-DAPP_VERSION=$Version` 这种不带引号的写法在 Windows
  #    PowerShell 5.1 里不展开变量（整段原样传给 cmake），必须先拼成
  #    单个参数传。VS 生成器是 multi-config，CMAKE_BUILD_TYPE 无意义不传。
  $launcherSrc = Join-Path $repo "apps\desktop\launcher-cpp"
  $launcherBuild = Join-Path $stage "launcher-build"
  $versionArg = "-DAPP_VERSION=$Version"
  cmake -S $launcherSrc -B $launcherBuild $versionArg
  if ($LASTEXITCODE -ne 0) { throw "cmake configure（引导器）失败" }
  cmake --build $launcherBuild --config Release
  if ($LASTEXITCODE -ne 0) { throw "cmake build（引导器）失败" }
  $launcher = Join-Path $launcherBuild "Release\fcp-launcher.exe"
  if (!(Test-Path $launcher)) {
    # 单配置生成器（如 Ninja + msbuild 变体）时产物不带 Release 子目录。
    if (Test-Path (Join-Path $launcherBuild "fcp-launcher.exe")) {
      $launcher = Join-Path $launcherBuild "fcp-launcher.exe"
    } else {
      throw "找不到 $launcher"
    }
  }

  # 2) 载荷 zip：整个收集目录递归入包（Qt 插件在 platforms/、styles/ 等子目录里）。
  #    .NET 的 ZipFile 用标准 deflate；引导器只启用了 deflate 解码。
  try {
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop
  } catch {
    # PowerShell 7 已经把程序集加载好了。
  }
  $payload = Join-Path $stage "payload.zip"
  [System.IO.Compression.ZipFile]::CreateFromDirectory(
    $PayloadDir, $payload,
    [System.IO.Compression.CompressionLevel]::Optimal, $false)

  # 3) 64 字节尾部：magic + 格式版本 + 偏移/长度 + SHA-256。
  $sha = (Get-FileHash -Algorithm SHA256 -LiteralPath $payload).Hash
  $hash = [byte[]]::new(32)
  for ($i = 0; $i -lt 32; $i++) {
    $hash[$i] = [Convert]::ToByte($sha.Substring($i * 2, 2), 16)
  }
  $offset = (Get-Item $launcher).Length
  $length = (Get-Item $payload).Length

  $footer = [byte[]]::new(64)
  [Text.Encoding]::ASCII.GetBytes("FCPBOOT1").CopyTo($footer, 0)
  [BitConverter]::GetBytes([uint32]1).CopyTo($footer, 8)   # 格式版本
  # 12..16 保留，保持 0
  [BitConverter]::GetBytes([uint64]$offset).CopyTo($footer, 16)
  [BitConverter]::GetBytes([uint64]$length).CopyTo($footer, 24)
  $hash.CopyTo($footer, 32)

  # 4) 拼接：引导器 + 载荷 + 尾部。
  $out = Join-Path $OutDir "fcp-client-gui-${Version}-windows-amd64.exe"
  $fs = [System.IO.File]::Create($out)
  try {
    foreach ($part in @($launcher, $payload)) {
      $bytes = [System.IO.File]::ReadAllBytes($part)
      $fs.Write($bytes, 0, $bytes.Length)
    }
    $fs.Write($footer, 0, $footer.Length)
  } finally { $fs.Close() }

  Write-Host ("便携 exe: {0} ({1:N1} MiB；载荷 {2:N1} MiB)" -f `
    $out, ((Get-Item $out).Length / 1MB), ($length / 1MB))
} finally {
  Remove-Item -Recurse -Force $stage -ErrorAction SilentlyContinue
}
