# 把 tauri build 出来的 FCP.exe（+ sidecar）打成单文件便携 exe。
#
# Tauri 自己的 NSIS/MSI 目标都是"安装器"；这里要的是"双击即用、删除即卸载"，
# 所以沿用仓库已有的 7zSD 自解压方案（packaging/windows/7zSD.sfx）：
#   7zSD.sfx + 配置 + 载荷(7z) -> FCP-<版本>-win64.exe
#
# 用法：
#   pwsh -File apps/desktop/scripts/bundle_windows_portable.ps1 `
#     -ExeDir apps\fcp-tauri\src-tauri\target\release [-Version 0.0.1]

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

$sevenZip = @(
  "${env:ProgramFiles}\7-Zip\7z.exe",
  "${env:ProgramFiles(x86)}\7-Zip\7z.exe"
) | Where-Object { Test-Path $_ } | Select-Object -First 1
if (!$sevenZip) { throw "需要 7-Zip（winget install 7zip.7zip）" }

$sfx = Join-Path $repo "packaging\windows\7zSD.sfx"
if (!(Test-Path $sfx)) { throw "缺少 $sfx" }

$stage = Join-Path ([System.IO.Path]::GetTempPath()) ("fcp-tauri-stage-" + [guid]::NewGuid())
New-Item -ItemType Directory -Force -Path $stage | Out-Null
try {
  Copy-Item $app (Join-Path $stage "FCP.exe")
  $sidecar = Get-ChildItem $ExeDir -Filter "fcp-client*.exe" |
             Where-Object { $_.Name -ne "FCP.exe" } | Select-Object -First 1
  if (!$sidecar) { throw "找不到 sidecar fcp-client*.exe" }
  Copy-Item $sidecar.FullName (Join-Path $stage "fcp-client.exe")

  $config = Join-Path $stage "config.txt"
  $confLines = @(
    ';!@Install@!UTF-8!',
    "Title=`"FCP $Version`"",
    'RunProgram="FCP.exe"',
    ';!@InstallEnd@!'
  )
  Set-Content -Path $config -Encoding utf8 -Value $confLines

  $payload = Join-Path $stage "payload.7z"
  & $sevenZip a -t7z -mx=9 (Join-Path $stage "payload.7z") `
      (Join-Path $stage "FCP.exe") (Join-Path $stage "fcp-client.exe") | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "7z 打包失败" }

  $out = Join-Path $OutDir "FCP-$Version-win64.exe"
  $fs = [System.IO.File]::Create($out)
  try {
    foreach ($part in @($sfx, $config, $payload)) {
      $bytes = [System.IO.File]::ReadAllBytes($part)
      $fs.Write($bytes, 0, $bytes.Length)
    }
  } finally { $fs.Close() }
  Write-Host "便携 exe: $out ($([math]::Round((Get-Item $out).Length / 1MB, 1)) MiB)"
} finally {
  Remove-Item -Recurse -Force $stage -ErrorAction SilentlyContinue
}
