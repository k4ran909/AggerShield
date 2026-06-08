# AggerShield agent installer (Windows / PowerShell).
#
# You give a customer this script + their license key + the aggershield.exe
# binary. It writes a config and runs the agent in front of their app.
#
#   $env:AGS_KEY="agsk_xxx"
#   $env:AGS_SERVER="https://license.yourdomain.com"
#   $env:AGS_UPSTREAM="http://127.0.0.1:3000"
#   .\install.ps1
#
param(
  [string]$Key       = $env:AGS_KEY,
  [string]$Server    = $env:AGS_SERVER,
  [string]$Upstream  = $env:AGS_UPSTREAM,
  [string]$Listen    = $(if ($env:AGS_LISTEN) { $env:AGS_LISTEN } else { ":8080" }),
  [string]$AgentBin  = $(if ($env:AGENT_BIN) { $env:AGENT_BIN } else { ".\aggershield.exe" }),
  [string]$Config    = ".\aggershield.config.json"
)

if (-not $Key)      { throw "set AGS_KEY (your license key, agsk_...)" }
if (-not $Server)   { throw "set AGS_SERVER (control-plane URL)" }
if (-not $Upstream) { throw "set AGS_UPSTREAM (your app origin)" }
if (-not (Test-Path $AgentBin)) { throw "agent binary not found at $AgentBin (set AGENT_BIN)" }

$cfg = [ordered]@{
  listen   = $Listen
  upstream = $Upstream
  license  = [ordered]@{
    enabled            = $true
    server_url         = $Server
    key                = $Key
    heartbeat_interval = "30s"
    fail_open          = $false
  }
  challenge  = [ordered]@{ enabled = $true; mode = "adaptive" }
  rate_limit = [ordered]@{ per_ip_rps = 20; per_ip_burst = 40; global_rps = 5000; global_burst = 10000 }
}
$cfg | ConvertTo-Json -Depth 6 | Out-File -Encoding utf8 $Config
Write-Host "wrote $Config — starting agent (Ctrl-C to stop)"
& $AgentBin -config $Config
