# 把 tauri build 出来的 FCP.exe（+ sidecar）打成单文件便携 exe。
#
# Tauri 自己的 NSIS/MSI 目标都是"安装器"；这里要的是"双击即用、删除即卸载"。
# 做法是一个很小的 Rust 引导器（apps/desktop/launcher）：
#
#   [fcp-launcher.exe][payload.zip][64 字节尾部]
#
# 首次运行时引导器把载荷解到 %LOCALAPPDATA%\FCP\bin\<SHA-256 前 8 字节>\，
# 之后直接启动缓存里的 FCP.exe；换新版本按内容哈希分目录，旧目录 7 天未用
# 自动清理。用户配置在 WebView 的 localStorage（按 com.fcp.client 标识），
# 与这个缓存目录无关，升级不需要重输。
#
# 用法：
#   pwsh -File apps/desktop/scripts/bundle_windows_portable.ps1 `
#     -ExeDir apps\desktop\src-tauri\target\release [-Version 0.0.1]

[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$ExeDir,
  [string]$Version,
  [string]$OutDir
)

$ErrorActionPreference = "Stop"
$repo = Resolve-Path (Join-Path $PSScriptRoot "..\..\..")
if (-not $Version) {
  $Version = (Get-Content (Join-Path $repo "VERSION") -Raw).Trim()
}
if (-not $OutDir) { $OutDir = Join-Path $repo "dist" }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$app = Join-Path $ExeDir "FCP.exe"
if (!(Test-Path $app)) { throw "找不到 $app；先运行 npm run tauri build" }
$sidecar = Get-ChildItem $ExeDir -Filter "fcp-client*.exe" |
           Where-Object { $_.Name -ne "FCP.exe" } | Select-Object -First 1
if (!$sidecar) { throw "找不到 sidecar fcp-client*.exe" }

if (-not [BitConverter]::IsLittleEndian) {
  throw "这个脚本假定小端主机（引导尾部的整数按小端写入）"
}

$stage = Join-Path ([System.IO.Path]::GetTempPath()) ("fcp-launcher-stage-" + [guid]::NewGuid())
New-Item -ItemType Directory -Force -Path $stage | Out-Null
try {
  # 载荷根目录只放运行需要的文件；version.txt 供排障时确认缓存对应哪个版本。
  $payloadDir = Join-Path $stage "payload"
  New-Item -ItemType Directory -Force -Path $payloadDir | Out-Null
  Copy-Item $app (Join-Path $payloadDir "FCP.exe")
  Copy-Item $sidecar.FullName (Join-Path $payloadDir "fcp-client.exe")
  Set-Content -Path (Join-Path $payloadDir "version.txt") -Encoding utf8 -Value "FCP $Version"

  # 1) 编译引导器。target-dir 显式指定，避免被外部 CARGO_TARGET_DIR 影响。
  $crateDir = Join-Path $repo "apps\desktop\launcher"
  $targetDir = Join-Path $crateDir "target"
  Push-Location $crateDir
  $prevVersion = $env:FCP_VERSION
  try {
    $env:FCP_VERSION = $Version
    cargo build --release --target-dir $targetDir
    if ($LASTEXITCODE -ne 0) { throw "cargo build（引导器）失败" }
  } finally {
    if ($null -eq $prevVersion) {
      Remove-Item Env:\FCP_VERSION -ErrorAction SilentlyContinue
    } else {
      $env:FCP_VERSION = $prevVersion
    }
    Pop-Location
  }
  $launcher = Join-Path $targetDir "release\fcp-launcher.exe"
  if (!(Test-Path $launcher)) { throw "找不到 $launcher" }

  # 2) 载荷 zip（.NET 的 ZipFile 用标准 deflate；引导器只启用了 deflate 解码）。
  try {
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop
  } catch {
    # PowerShell 7 已经把程序集加载好了。
  }
  $payload = Join-Path $stage "payload.zip"
  if (Test-Path $payload) { Remove-Item -Force $payload }
  [System.IO.Compression.ZipFile]::CreateFromDirectory(
    $payloadDir, $payload,
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
