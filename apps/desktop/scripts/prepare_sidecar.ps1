# 把已构建的 fcp-client 放进 Tauri 的 sidecar 目录。
#
# Tauri 的 externalBin 要求文件名带目标三元组后缀：
#   src-tauri/binaries/fcp-client-x86_64-pc-windows-msvc.exe
# （Linux 上是 fcp-client-x86_64-unknown-linux-gnu，由 VPS 脚本负责。）
#
# 用法（先在仓库根 configure/build 出 fcp-client）：
#   pwsh -File apps/desktop/scripts/prepare_sidecar.ps1 -BinDir build\windows-x64\Release

[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$BinDir,
  [string]$Target = "x86_64-pc-windows-msvc"
)

$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $PSScriptRoot
$src = Join-Path $BinDir "fcp-client.exe"
if (!(Test-Path $src)) {
  # 单配置生成器（Ninja）把 exe 直接放在 -B 目录下。
  $src = Join-Path $BinDir "fcp-client.exe"
}
if (!(Test-Path $src)) {
  throw "找不到 $src；先构建 FCP_BUILD_PROXY=ON 的 fcp-client"
}
$dstDir = Join-Path $here "src-tauri\binaries"
New-Item -ItemType Directory -Force -Path $dstDir | Out-Null
$dst = Join-Path $dstDir "fcp-client-$Target.exe"
Copy-Item $src $dst -Force
Write-Host "sidecar: $dst"
