# AggerShield cross-compile (Windows / PowerShell equivalent of `make release`).
# Produces distributable binaries in .\dist for every target platform.
param([string]$Version = $(try { (git describe --tags --always --dirty) } catch { "dev" }))

$ErrorActionPreference = "Stop"
$ldflags = "-s -w -X main.agentVersion=$Version"
$platforms = @(
  @{os="linux";   arch="amd64"}, @{os="linux";   arch="arm64"},
  @{os="darwin";  arch="amd64"}, @{os="darwin";  arch="arm64"},
  @{os="windows"; arch="amd64"}
)
New-Item -ItemType Directory -Force -Path dist | Out-Null
foreach ($p in $platforms) {
  $ext = if ($p.os -eq "windows") { ".exe" } else { "" }
  Write-Host "building $($p.os)/$($p.arch)"
  $env:GOOS = $p.os; $env:GOARCH = $p.arch; $env:CGO_ENABLED = "0"
  & go build -ldflags $ldflags -o "dist/aggershield_$($p.os)_$($p.arch)$ext" ./cmd/aggershield
  & go build -ldflags $ldflags -o "dist/aggershield-server_$($p.os)_$($p.arch)$ext" ./cmd/aggershield-server
}
Remove-Item Env:GOOS, Env:GOARCH, Env:CGO_ENABLED
Write-Host "done -> .\dist"
