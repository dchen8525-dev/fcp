# Windows 一键构建：sidecar 准备 → tauri build（--no-bundle）→ 7zSD 便携单文件。
#
# 用法（在 VS 开发者命令行或已装好 Rust/Node 的环境里）：
#   pwsh -File apps/desktop/scripts/build_windows.ps1 `
#     -ProxyBin build\release-win\apps\cli\Release\fcp-client.exe
#
# 参数：
#   -ProxyBin   已构建的 fcp-client.exe（缺省按常见构建目录自动找）
#   -TargetDir  tauri 的 target 目录（缺省 src-tauri\target\release）

[CmdletBinding()]
param(
  [string]$ProxyBin,
  [string]$TargetDir
)

$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $PSScriptRoot
$repo = Resolve-Path (Join-Path $here "..\..")

if (-not $ProxyBin) {
  $candidates = @(
    (Join-Path $repo "build\release-win\apps\cli\Release\fcp-client.exe"),
    (Join-Path $repo "build\proxy-check\apps\cli\Release\fcp-client.exe"),
    (Join-Path $repo "build\windows-x64\apps\cli\Release\fcp-client.exe"),
    (Join-Path $repo "build\windows-x64\apps\cli\Debug\fcp-client.exe")
  )
  $ProxyBin = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
  if (-not $ProxyBin) {
    throw "找不到 fcp-client.exe；用 -ProxyBin 指定，或先构建 FCP_BUILD_PROXY=ON"
  }
}
Write-Host "== sidecar: $ProxyBin"
& (Join-Path $PSScriptRoot "prepare_sidecar.ps1") -BinDir (Split-Path -Parent $ProxyBin)

Push-Location $here
try {
  if (!(Test-Path "node_modules")) { npm install --no-audit --no-fund }
  npx tauri build --no-bundle
  if ($LASTEXITCODE -ne 0) { throw "tauri build 失败" }
} finally { Pop-Location }

if (-not $TargetDir) { $TargetDir = Join-Path $here "src-tauri\target\release" }
& (Join-Path $PSScriptRoot "bundle_windows_portable.ps1") -ExeDir $TargetDir
