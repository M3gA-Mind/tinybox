# Provide the POSIX shell required by the detached-process fixtures.
param([Parameter(Mandatory = $true)][string]$PosixBin)
$ErrorActionPreference = "Stop"
$root = [System.IO.Path]::GetPathRoot((Get-Location).Path)
$bin = Join-Path $root "bin"
if (-not (Test-Path $bin)) {
    New-Item -ItemType Junction -Path $bin -Target $PosixBin | Out-Null
}
if (-not (Test-Path (Join-Path $bin "sh.exe"))) {
    throw "The native /bin/sh fixture is unavailable at $bin"
}
