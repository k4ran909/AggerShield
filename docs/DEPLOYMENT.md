# AggerShield — Deployment Guide

Production deployment of AggerShield in front of a web app, the way it was
actually rolled out and tested: a **DigitalOcean droplet** behind **Cloudflare**,
protecting an app on the same host.

```
visitor ──► Cloudflare (free: volumetric L3/L4 + public TLS)
            │
            ▼
        your droplet :80/:443  ──►  AggerShield (L7 defence)  ──►  your app (127.0.0.1:3000)
```

**Why this shape?** A host-based proxy cannot absorb a volumetric flood — the
uplink saturates upstream of any software. Cloudflare's edge soaks that for free;
AggerShield does the smart Layer-7 work (rate limiting, bans, proof-of-work
challenge, per-route rules, tarpit, fleet bans, the security monitor). For the
*volumetric* layer AggerShield can also **trigger** edge mitigation via its
scrubber integration, but the absorption itself happens at the edge.

> Tested on: Ubuntu 24.04 (x86_64), a DigitalOcean droplet behind Cloudflare,
> app on `127.0.0.1:3000`. (Use your own droplet IP / domain below — never
> publish your origin IP, or attackers can bypass Cloudflare and hit it directly.)

---

## 1. Prerequisites

- A VPS (Ubuntu 22.04/24.04, x86_64 or arm64). 1–2 vCPU / 1–4 GB is plenty —
  AggerShield's data plane runs ~1.9M req/s per core.
- A domain added to **Cloudflare** and showing **Active**.
- Your web app reachable on the droplet at `127.0.0.1:3000` (or any local port).
- Root (or sudo) on the droplet.

---

## 2. Quick setup (one script)

Run this in a root shell on the droplet. It frees disk, builds AggerShield,
writes a config, installs the systemd service, and locks the firewall to
Cloudflare. It serves plain HTTP on `:80` (use Cloudflare SSL mode **Flexible**);
see §6 to upgrade to end-to-end TLS.

```bash
# install Go 1.26 (Ubuntu's apt Go is too old)
curl -fsSLO https://go.dev/dl/go1.26.2.linux-amd64.tar.gz
rm -rf /usr/local/go && tar -C /usr/local -xzf go1.26.2.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc && export PATH=$PATH:/usr/local/go/bin

# build
cd /opt && git clone https://github.com/k4ran909/AggerShield.git && cd AggerShield
go build -ldflags "-s -w" -o /usr/local/bin/aggershield ./cmd/aggershield
id aggershield >/dev/null 2>&1 || useradd --system --no-create-home aggershield
mkdir -p /etc/aggershield /var/lib/aggershield && chown aggershield:aggershield /var/lib/aggershield

# config (auto-generates an admin token — SAVE the printed value)
TOKEN=$(openssl rand -hex 24)
cat > /etc/aggershield/config.json <<JSON
{
  "listen": ":80",
  "upstream": "http://127.0.0.1:3000",
  "trusted_proxies": [
    "173.245.48.0/20","103.21.244.0/22","103.22.200.0/22","103.31.4.0/22",
    "141.101.64.0/18","108.162.192.0/18","190.93.240.0/20","188.114.96.0/20",
    "197.234.240.0/22","198.41.128.0/17","162.158.0.0/15","104.16.0.0/13",
    "104.24.0.0/14","172.64.0.0/13","131.0.72.0/22"
  ],
  "rate_limit": { "per_ip_rps": 20, "per_ip_burst": 40, "global_rps": 5000, "global_burst": 10000 },
  "ban": { "base_duration": "60s", "max_duration": "1h", "escalation_factor": 2.0, "persist_path": "/var/lib/aggershield/bans.json" },
  "challenge": { "enabled": true, "mode": "adaptive" },
  "tarpit": { "enabled": true, "delay": "5s", "max_concurrent": 4096 },
  "monitor": { "sample_interval": "1s", "retain": 3600, "attack_threshold": 20, "exit_intervals": 5 },
  "admin": { "enabled": true, "token": "$TOKEN", "protect_telemetry": true },
  "log": { "level": "info", "format": "json" }
}
JSON
echo "ADMIN TOKEN: $TOKEN"

# service
cp /opt/AggerShield/deploy/aggershield-agent.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now aggershield-agent

# firewall: only Cloudflare may reach :80/:443; SSH stays open
cd /opt/AggerShield && bash deploy/cloudflare-ufw.sh
```

Then in Cloudflare: **DNS** → `A` record → your subdomain → droplet IP →
**Proxied (orange)**, and **SSL/TLS → Overview → Flexible**.

---

## 3. Manual setup (step by step)

If you'd rather understand each step, do these one at a time.

### 3.1 Install Go 1.26
```bash
curl -fsSLO https://go.dev/dl/go1.26.2.linux-amd64.tar.gz
rm -rf /usr/local/go && tar -C /usr/local -xzf go1.26.2.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc && export PATH=$PATH:/usr/local/go/bin
go version    # expect go1.26.x
```

### 3.2 Build AggerShield
```bash
cd /opt && git clone https://github.com/k4ran909/AggerShield.git
cd /opt/AggerShield
go build -ldflags "-s -w" -o /usr/local/bin/aggershield ./cmd/aggershield   # first build is silent ~30s
ls -lh /usr/local/bin/aggershield    # ~8 MB
```

### 3.3 Service user + dirs
```bash
useradd --system --no-create-home aggershield 2>/dev/null || true
mkdir -p /etc/aggershield /var/lib/aggershield
chown aggershield:aggershield /var/lib/aggershield
```

### 3.4 Config
Copy the Cloudflare example and edit it:
```bash
cp /opt/AggerShield/deploy/config.cloudflare.example.json /etc/aggershield/config.json
TOKEN=$(openssl rand -hex 24)
sed -i "s/CHANGE_ME_TO_A_LONG_RANDOM_SECRET/$TOKEN/" /etc/aggershield/config.json
echo "ADMIN TOKEN: $TOKEN"      # save this
nano /etc/aggershield/config.json   # set "upstream" if your app isn't on 127.0.0.1:3000
```

### 3.5 systemd service
```bash
cp /opt/AggerShield/deploy/aggershield-agent.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now aggershield-agent
systemctl status aggershield-agent --no-pager   # want: active (running)
```

### 3.6 Firewall — lock the origin to Cloudflare
Critical: if attackers learn your droplet's raw IP they can bypass Cloudflare and
hit you directly. Allow `:80/:443` only from Cloudflare's ranges (SSH stays open):
```bash
cd /opt/AggerShield && bash deploy/cloudflare-ufw.sh
```

### 3.7 Cloudflare DNS + SSL
- **DNS** → `A` → subdomain → droplet IP → **Proxied (orange cloud)**.
- **SSL/TLS → Overview → Flexible** (HTTP origin) or **Full (strict)** (see §6).

---

## 4. Verify

```bash
systemctl status aggershield-agent --no-pager
curl -s -o /dev/null -w "local  -> %{http_code}\n" http://127.0.0.1/        # via AggerShield → app
curl -s -o /dev/null -w "public -> %{http_code}\n" https://YOUR-DOMAIN/      # full chain through Cloudflare
```
A real HTTP code (200/403/502) on the public URL means the whole chain works.
`502` just means AggerShield is up but your app isn't answering on the upstream.

---

## 5. Day-to-day operations

```bash
journalctl -u aggershield-agent -f                 # live logs
systemctl restart aggershield-agent                # restart
```

**Hot-reload config without downtime** (after editing `/etc/aggershield/config.json`):
```bash
TOKEN=...                                            # your admin token
curl -X POST -H "X-AggerShield-Token: $TOKEN" http://127.0.0.1/aggershield/admin/reload
```

**Observability** (with `protect_telemetry: true` these require the token):
- Security dashboard (live charts + attack log): `https://YOUR-DOMAIN/aggershield/security`
- Prometheus metrics: `/metrics` · JSON stats: `/aggershield/stats`
- Attack events JSON: `/aggershield/events` · time-series: `/aggershield/timeseries`

**Admin API** (token via `X-AggerShield-Token` header):
- `GET /aggershield/admin/bans` · `POST /aggershield/admin/ban?ip=…&for=…` · `…/unban?ip=…`
- `POST /aggershield/admin/mode?challenge=always|adaptive` (under-attack switch)
- `POST /aggershield/admin/scrub?action=engage|disengage` (upstream scrubber)

---

## 6. Upgrade to end-to-end TLS (Full strict)

Flexible leaves the Cloudflare↔origin hop unencrypted. For end-to-end TLS, use a
Cloudflare **Origin Certificate** (free, 15-year):

1. Cloudflare → **SSL/TLS → Origin Server → Create Certificate** (defaults; the
   `*.yourdomain` wildcard covers your subdomain).
2. On the droplet:
   ```bash
   nano /etc/aggershield/origin.pem    # paste "Origin Certificate"
   nano /etc/aggershield/origin.key    # paste "Private Key"
   chown aggershield:aggershield /etc/aggershield/origin.* && chmod 640 /etc/aggershield/origin.*
   ```
3. Switch the config's `tls` block on:
   ```json
   "tls": { "enabled": true, "https_listen": ":443", "http_listen": ":80",
            "redirect_http": true,
            "cert_file": "/etc/aggershield/origin.pem", "key_file": "/etc/aggershield/origin.key" }
   ```
   (and remove/ignore the plain `"listen"` line — TLS uses `https_listen`).
4. `systemctl restart aggershield-agent`
5. Cloudflare → **SSL/TLS → Overview → Full (strict)**.

> **Automatic Let's Encrypt** is also supported (`tls.auto_cert`) if you point the
> domain *directly* at the droplet without Cloudflare — needs :80/:443 reachable
> from the internet. Don't use it behind Cloudflare; use the Origin cert instead.

---

## 7. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `cat: write error: No space left on device` | **Disk full** (Go build/module cache, journald) | `go clean -cache -modcache`, `journalctl --vacuum-size=100M`, `apt-get clean`, then `df -h /` |
| `self-check -> 000` / service won't start | Bad/empty config (often a side effect of a full disk) or port in use | `journalctl -u aggershield-agent -n 30 --no-pager`; check the config wrote: `tail /etc/aggershield/config.json` |
| `502 Bad Gateway` | App not listening on `upstream` | start your app on `127.0.0.1:3000` or fix `"upstream"` + restart |
| Public URL fails but local works | DNS/Cloudflare/firewall | DNS record proxied? SSL mode set? firewall allows Cloudflare? |
| Origin shows Cloudflare's IP, not the visitor's | `trusted_proxies` missing Cloudflare ranges | ensure the Cloudflare CIDRs are in `trusted_proxies` (verify the live list at cloudflare.com/ips) |
| Locked out after firewall | ufw blocked SSH | DigitalOcean **web console** → `ufw allow 22/tcp` |
| `go: go.mod file not found` | Ran `go build` from the wrong dir | `cd /opt/AggerShield` first |

---

## 8. Hardening checklist

- [ ] **Rotate any password you pasted anywhere**; use SSH keys, disable root password login.
- [ ] Firewall locks `:80/:443` to Cloudflare only (§3.6); SSH restricted to your IP if possible.
- [ ] `admin.token` is long and random; `protect_telemetry: true` so dashboards aren't public.
- [ ] End-to-end TLS via Origin cert (§6), Cloudflare SSL = **Full (strict)**.
- [ ] `allowlist` includes payment webhooks / health checks / your office IP.
- [ ] Keep Cloudflare IP ranges fresh (re-run `deploy/cloudflare-ufw.sh` periodically).
- [ ] Note: **JA3/JA4 fingerprinting is disabled behind Cloudflare** (you'd see CF's TLS, not the visitor's) — rely on Cloudflare Bot Management for that tier.

See [TESTING.md](TESTING.md) to stress-test the deployment.
