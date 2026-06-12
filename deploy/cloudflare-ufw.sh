#!/usr/bin/env bash
# Lock the origin so ONLY Cloudflare can reach :80/:443 — otherwise an attacker
# who learns your droplet's IP just bypasses Cloudflare and hits you directly.
# Pulls Cloudflare's current IP ranges and configures ufw. Keeps SSH (22) open.
#
#   sudo bash deploy/cloudflare-ufw.sh
#
set -euo pipefail
command -v ufw >/dev/null || { echo "installing ufw..."; apt-get update -y && apt-get install -y ufw; }

echo "Resetting ufw and allowing SSH..."
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp comment 'SSH'

echo "Allowing 80/443 from Cloudflare ranges only..."
for url in https://www.cloudflare.com/ips-v4 https://www.cloudflare.com/ips-v6; do
  while read -r cidr; do
    [ -n "$cidr" ] || continue
    ufw allow from "$cidr" to any port 80  proto tcp comment 'Cloudflare'
    ufw allow from "$cidr" to any port 443 proto tcp comment 'Cloudflare'
  done < <(curl -fsS "$url")
done

ufw --force enable
ufw status numbered
echo
echo "Done. Only Cloudflare can reach :80/:443; SSH stays open to all."
echo "NOTE: keep this list fresh — re-run after Cloudflare changes ranges."
