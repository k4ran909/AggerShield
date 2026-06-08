#!/usr/bin/env bash
# AggerShield agent installer (Linux).
#
# You give a customer this script + their license key. It writes a config and
# runs the AggerShield agent in front of their app. The agent validates the key
# against your control plane and heartbeats telemetry; if you revoke the key it
# fails closed.
#
# The agent itself is the compiled `aggershield` binary — your protection logic
# ships as a binary, not source. Place that binary next to this script (or set
# AGENT_BIN), then:
#
#   AGS_KEY=agsk_xxx \
#   AGS_SERVER=https://license.yourdomain.com \
#   AGS_UPSTREAM=http://127.0.0.1:3000 \
#   AGS_LISTEN=:8080 \
#   ./install.sh
#
set -euo pipefail

: "${AGS_KEY:?set AGS_KEY to your license key (agsk_...)}"
: "${AGS_SERVER:?set AGS_SERVER to the control-plane URL}"
: "${AGS_UPSTREAM:?set AGS_UPSTREAM to your app's origin, e.g. http://127.0.0.1:3000}"
AGS_LISTEN="${AGS_LISTEN:-:8080}"
AGENT_BIN="${AGENT_BIN:-./aggershield}"
CONFIG="${CONFIG:-./aggershield.config.json}"

if [[ ! -x "$AGENT_BIN" ]]; then
  echo "agent binary not found/executable at: $AGENT_BIN" >&2
  echo "place the aggershield binary there or set AGENT_BIN" >&2
  exit 1
fi

cat > "$CONFIG" <<JSON
{
  "listen": "${AGS_LISTEN}",
  "upstream": "${AGS_UPSTREAM}",
  "license": {
    "enabled": true,
    "server_url": "${AGS_SERVER}",
    "key": "${AGS_KEY}",
    "heartbeat_interval": "30s",
    "fail_open": false
  },
  "challenge": { "enabled": true, "mode": "adaptive" },
  "rate_limit": { "per_ip_rps": 20, "per_ip_burst": 40, "global_rps": 5000, "global_burst": 10000 }
}
JSON

echo "wrote $CONFIG — starting agent (Ctrl-C to stop)"
exec "$AGENT_BIN" -config "$CONFIG"
