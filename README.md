# 🛡️ AggerShield

![CI](https://github.com/k4ran909/AggerShield/actions/workflows/ci.yml/badge.svg)

A cross-platform **Layer-7 (application-layer) DDoS protection reverse proxy**, written in Go (standard library only — the one external dependency, `x/crypto`, is used solely for optional ACME/Let's Encrypt auto-HTTPS). It sits in front of a web app, ecommerce site, or game-server web panel and absorbs application-layer abuse — HTTP floods, slow attacks, and noisy sources — before they reach your backend.

**Data-plane performance:** ~**522 ns/request** through the full guard pipeline (≈1.9M req/s per core, single-threaded; `go test -bench=. ./internal/guard`).

> **Scope, stated honestly.** A piece of software running on (or in front of) your server **cannot stop a volumetric L3/L4 flood.** If a botnet throws 500 Gbps at a 1–10 Gbps uplink, the pipe is saturated *upstream of you* — no host-based tool can fix a full pipe. That class of attack is handled at the network edge (OVH VAC, Cloudflare, AWS Shield, BGP blackholing). AggerShield defends the layer it actually can: **L7 + connection level.** For volumetric protection, pair it with an upstream scrubber.

## Why per-IP rate limiting alone is not enough

A naive "ban any IP that sends too many requests" is trivially bypassed, and this project is built around the bypasses:

| Attacker move | Why naive limiting fails | AggerShield's answer |
|---|---|---|
| 10k+ IPs each *under* the per-IP limit | No single IP trips the threshold | **Global aggregate limiter** sheds excess total traffic |
| Spoofed source IPs (L3/L4) | Banning a forged IP is useless and bans innocents | Bans only apply to completed HTTP requests; XFF trusted only from configured proxies |
| Flood of unique IPs to bloat the ban table | The ban table becomes the memory-DoS | **Size-capped** table + idle-bucket GC; soonest-to-expire eviction |
| Slowloris / RUDY low-and-slow | Request-rate limit never trips | **Per-IP concurrency cap** + strict read/header timeouts |
| Repeat offenders returning | Fixed bans are cheap to wait out | **Escalating ban durations** (exponential backoff) |
| Locking out admins / payment webhooks | Collateral damage | **Allowlist** that always passes |
| Botnet whose IPs each stay *under* every limit | Nothing trips | **Proof-of-work challenge**: a bot that can't run JS never passes |

## Architecture

```
client ──► AggerShield (L7 guard) ──► your upstream (app / store / panel)
              │
              ├─ resolve real client IP (peer addr, or trusted XFF)
              ├─ allowlist        → always pass
              ├─ denylist         → always block
              ├─ per-route rule   → allow / block / force-challenge / default
              ├─ ban check        → block if currently banned
              ├─ bad user-agent   → block known bad bots
              ├─ challenge gate   → PoW interstitial unless cleared
              │                     (always-on, or adaptive under load)
              ├─ global limiter   → 503 if total traffic over ceiling
              ├─ per-IP limiter   → 429 + escalating ban (route override aware)
              ├─ per-IP conn cap  → 429 if too many concurrent
              └─ body size cap    → bounded memory per request

           policy is held behind an atomic pointer → hot-reloadable with no downtime
```

### The proof-of-work challenge (botnet defence)

When a botnet spreads across enough IPs that no single one trips a limit, the
only thing that distinguishes good from bad is *whether the client is a real
browser*. The challenge gate serves a tiny interstitial page whose JavaScript
must find a nonce so that `SHA-256(token:nonce)` has N leading zero bits. A
real browser solves it invisibly (~1s) and gets a **signed, stateless
clearance cookie**; a flood client that doesn't run JS can never pass.

- **Stateless:** challenge params are HMAC-signed, so the server stores
  nothing and a client can't forge an easier difficulty.
- **`mode: "always"`** challenges every uncleared client (under-attack mode).
- **`mode: "adaptive"`** only challenges once the global limiter is under
  pressure — invisible in normal traffic, automatic when flooded.
- Passing the challenge is **not** immunity: per-IP and global limits still
  police cleared clients.

> Note: the browser solver uses `crypto.subtle`, which needs a secure context
> — serve AggerShield over **HTTPS** (or localhost) in production.

Server-level `Read/ReadHeader/Write/Idle` timeouts form the front line against slow attacks. A background sweeper performs **auto-unban** once a ban's TTL expires.

### Packages
- `internal/config` — JSON config + defaults (durations as `"60s"` strings)
- `internal/netutil` — client-IP resolution & CIDR matching
- `internal/ratelimit` — per-IP and global token buckets (with idle GC)
- `internal/banlist` — TTL ban store, escalation, auto-unban, memory cap
- `internal/connlimit` — per-IP concurrency cap (slow-attack defence)
- `internal/challenge` — stateless proof-of-work browser challenge
- `internal/rules` — per-route matcher (prefix/regex/method → action + rate override)
- `internal/policy` — immutable, atomically-swappable policy snapshot (hot-reload)
- `internal/guard` — composes the pipeline into one `http.Handler` + `Reload()`
- `internal/admin` — token-protected runtime control API
- `internal/proxy` — multi-site host-routing reverse proxy (Host + forwarded headers)
- `internal/tlsutil` — HTTPS termination (ACME/Let's Encrypt, cert files, or dev self-signed)
- `internal/mcproxy` — protocol-aware Minecraft TCP proxy
- `internal/license` — license key store + agent client (the licensing model)
- `cmd/aggershield-server` — central control plane + admin dashboard
- `client/` — agent installer scripts handed to users (`install.sh`/`.ps1`)
- `internal/metrics` — atomic counters + `/aggershield/stats`
- `detector/` — Python ML/anomaly control plane (EWMA + XGBoost/CICDDoS2019)
- `cmd/origin` — demo backend; `cmd/flood` — demo load generator (incl. `-solve`)

## Quick start

```bash
go build ./...

# 1) point config.json "upstream" at your real backend
# 2) run it
go run ./cmd/aggershield -config config.json
```

AggerShield listens on `:8080` (configurable) and proxies to `upstream`.

- Live stats:  `GET /aggershield/stats`  → JSON counters (requests, bans, rate-limits)
- Health:      `GET /aggershield/health`

### Configuration (`config.json`)

| Key | Meaning |
|---|---|
| `listen` / `upstream` | HTTP bind address / default backend origin |
| `sites` | host-based routing: `[{host, upstream, preserve_host}]` (multi-site) |
| `tls` | HTTPS termination: `enabled`, `cert_file`/`key_file` or `self_signed`, `https_listen`, `http_listen`, `redirect_http` |
| `allowlist` | IPs/CIDRs never limited or banned (admins, webhooks) |
| `dry_run` | monitor-only: log decisions, block nothing (safe rollout) |
| `challenge.challenge_non_browser` | `false` (default) = only challenge browser navigations |
| `trusted_proxies` | only these peers may set `X-Forwarded-For` |
| `rate_limit.per_ip_rps` / `per_ip_burst` | single-source budget |
| `rate_limit.global_rps` / `global_burst` | aggregate ceiling (distributed-flood defence) |
| `ban.base_duration` / `max_duration` / `escalation_factor` | ban length & escalation |
| `ban.sweep_interval` | how often expired bans are auto-removed |
| `ban.max_entries` | hard cap on tracked IPs (anti-self-DoS) |
| `connection.max_per_ip` | concurrent requests per IP |
| `connection.*_timeout`, `max_*_bytes` | slow-attack & size limits |
| `denylist` | IPs/CIDRs always blocked outright |
| `bad_user_agents` | case-insensitive UA substrings to block |
| `block.status` / `block.message` | customise the response to blocked requests |
| `challenge.*` | PoW challenge (see above) incl. `pressure_threshold` for adaptive |
| `admin.enabled` / `admin.token` | runtime control API (see below) |
| `log.level` / `log.format` | `debug\|info\|warn\|error` and `text\|json` |
| `watch_interval` | `>0` to auto hot-reload the config file on change |
| `rules` | per-route overrides (see below) |

### Per-route rules

Attacks target expensive endpoints (login, search, checkout), not your whole
site uniformly. Rules give each route its own policy — evaluated top-to-bottom,
first match wins:

```json
"rules": [
  { "name": "block-scanners",  "path_prefix": "/wp-admin", "action": "block" },
  { "name": "allow-health",    "path_prefix": "/healthz",  "action": "allow" },
  { "name": "challenge-login", "path_regex": "^/login", "methods": ["POST"], "action": "challenge" },
  { "name": "tight-checkout",  "path_prefix": "/api/checkout", "per_ip_rps": 2, "per_ip_burst": 3 }
]
```

- `action`: `allow` (skip all checks), `block` (always block), `challenge`
  (force PoW), or omit for the default pipeline.
- `path_prefix` / `path_regex` / `methods` define the match (any combination).
- `per_ip_rps` / `per_ip_burst` give a route its own stricter rate budget.

### Runtime control API (hot-reload, live ban/unban)

Enable `admin` and send `X-AggerShield-Token: <token>` on every call:

```bash
curl -H "$T" http://127.0.0.1:8080/aggershield/admin/bans            # list active bans
curl -H "$T" http://127.0.0.1:8080/aggershield/admin/config          # effective config (redacted)
curl -X POST -H "$T" ".../admin/ban?ip=1.2.3.4&for=2m"               # manual ban
curl -X POST -H "$T" ".../admin/unban?ip=1.2.3.4"                    # lift a ban
curl -X POST -H "$T" ".../admin/reload"                              # re-read config, hot-swap
```

Config is **hot-reloadable** three ways: the `reload` endpoint, a `SIGHUP`
signal, or `watch_interval` (auto-reload on file change). The guard reads its
policy from an atomically-swapped snapshot, so reloads apply with zero
downtime and no dropped connections. (Server-level timeouts and the challenge
secret are the only restart-only settings.)

## Run it as a service (licensing + central control plane)

AggerShield can run as a **product you operate**: you host a central control
plane, hand each user a **license key** + the agent, and manage everything from
an admin dashboard. The protection logic ships as a compiled binary — users
never get your source.

```
            your infrastructure                         customer's server
   ┌──────────────────────────────┐              ┌───────────────────────────┐
   │  aggershield-server           │  validate /  │  aggershield (agent)       │
   │  • issues / revokes keys      │◄─ heartbeat ─┤  • runs in front of their  │
   │  • admin dashboard (/admin)   │   (key auth) │    app, key-gated          │
   │  • sees every agent + its IP  │              │  • fails closed if revoked │
   └──────────────────────────────┘              └───────────────────────────┘
```

**1. Run the control plane (you):**

```bash
go run ./cmd/aggershield-server -admin-token "$(openssl rand -hex 16)"
# dashboard at http://localhost:9000/admin  (Basic auth: any user, password = token)
```

The dashboard lists every key, its status, and the live agent using it — the
**hostname, source IP, what it's protecting, last-seen, and request/ban
counts**. Issue a key with the form; revoke with one click.

**2. Give a user their key + the agent.** They run `client/install.sh`
(or `install.ps1`) with their key:

```bash
AGS_KEY=agsk_… AGS_SERVER=https://license.you.com AGS_UPSTREAM=http://127.0.0.1:3000 ./install.sh
```

The agent validates the key on start and heartbeats every 30s. **Revoke the key
in the dashboard and the agent fails closed (503) within one heartbeat** — your
central kill switch. (`license.fail_open: true` flips this to keep serving
unprotected instead.)

Agent config block:

```json
"license": {
  "enabled": true,
  "server_url": "https://license.you.com",
  "key": "agsk_…",
  "heartbeat_interval": "30s",
  "fail_open": false
}
```

### Push protection policy from the dashboard

You don't have to edit a customer's config to tune their protection — push a
**policy** to their key from the control plane and the agent applies it live on
its next heartbeat (no redeploy, no restart). Each key's row in `/admin` has a
**policy editor**: paste a partial JSON policy and hit "Push policy".

```json
{ "dry_run": true,
  "rules": [{ "name": "block-admin", "path_prefix": "/wp-admin", "action": "block" }],
  "rate_limit": { "per_ip_rps": 10, "per_ip_burst": 20 } }
```

Only the fields you set are overridden; everything else stays as the agent's
local config. Deployment/wiring (`listen`, `upstream`, `tls`, the license key,
the challenge secret) is **never** pushable — only protection settings
(rate limits, bans, challenge, rules, denylist, bad-UAs, block response,
`dry_run`). Each change bumps a version; agents apply it only when it moves, and
the policy persists on the control plane.

> **Hardening built in:** agent endpoints (`/validate`, `/heartbeat`) are
> per-IP rate-limited (`-agent-rps`/`-agent-burst`) so bad keys can't abuse the
> control plane; keys are stored only as SHA-256 hashes (a data-file leak can't
> be replayed); the admin token compares in constant time. Run the control
> plane over **HTTPS** in production (the server takes `-cert`/`-key`, and warns
> on startup if TLS is off) — keys travel in a header.

## Build, deploy & observe

**Get distributable binaries** (what you hand to users + run yourself):

```bash
make release        # cross-compiles agent + server for linux/darwin/windows → ./dist
#   or on Windows:  ./build.ps1
make build          # just this machine → ./bin
make test           # go test -race ./...
```

A version tag triggers a full **GitHub Release** (binaries + checksums + archives
bundling the client/ and deploy/ files) via GoReleaser:

```bash
git tag v0.1.0 && git push origin v0.1.0
```

**Docker** (one image, both binaries):

```bash
docker build -t aggershield .
docker run -p 8080:8080 -v "$PWD/config.json:/config.json" aggershield          # agent
docker run -p 9000:9000 --entrypoint /usr/local/bin/aggershield-server \
    -e AGGERSHIELD_ADMIN_TOKEN=secret aggershield                                # control plane
```

**systemd** units (with sandboxing + `CAP_NET_BIND_SERVICE` for :80/:443) are in
[`deploy/`](deploy/) — `aggershield-agent.service` and `aggershield-server.service`.

**Metrics:** both the agent and the control plane expose Prometheus metrics at
`GET /metrics` (no client-library dependency). Scrape them with Prometheus and
chart/alert in Grafana — e.g. alert on a spike in
`aggershield_rate_limited_global_total` or when `aggershield_uptime_seconds`
resets (an agent restarted/died). `GET /aggershield/stats` still serves the same
data as JSON.

## Will it affect normal users?

It's designed not to, and the defaults are conservative — but any DDoS filter
*can* cause false positives if misconfigured. The safeguards:

- **`dry_run: true`** — the recommended way to roll out. AggerShield logs every
  decision it *would* make (`reason`, `ip`, `path`) and increments
  `would_block_dry_run` in `/aggershield/stats`, but **blocks nothing**. Run it
  against real traffic for a day; if the would-block count only contains
  attackers, switch `dry_run` off to enforce.
- **`challenge.mode: "adaptive"`** (default) — the PoW challenge is invisible
  in normal traffic; it only kicks in when the global limiter is under
  pressure (i.e. during an attack).
- **`challenge_non_browser: false`** (default) — only browser navigations
  (`Accept: text/html`) are ever challenged, so your **APIs, mobile apps,
  webhooks, and XHR/asset requests are never asked to solve a PoW**.
- **`allowlist`** — never touch payment webhooks, health checks, monitoring,
  or known-good office IPs.

Things to tune for *your* traffic so real users aren't caught:

| Watch out for | Why | Fix |
|---|---|---|
| **CGNAT / mobile / office IPs** | thousands of real users share one IP | raise per-IP limits; allowlist known ranges |
| **SEO crawlers (Googlebot)** can't solve PoW | `mode:"always"` would de-index you | keep `adaptive`; allowlist verified crawler IPs |
| **File uploads** | `max_body_bytes` (1 MiB default) rejects big bodies | raise it, or a rule for the upload route |
| **Peak legitimate traffic** | a too-low `global_rps` sheds real users (503) | set the ceiling above your real peak |
| **Bad-UA substrings** | `"bot"` also matches `"Googlebot"` | keep the list specific |

## Protecting a hosted site (Vercel, Dokploy, any origin)

AggerShield protects traffic that flows **through** it, so you put it in the
request path and point your domain at it:

```
visitor → DNS (your domain) → AggerShield (your VPS) → origin (Vercel / Dokploy / app)
```

It terminates HTTPS, applies the full protection pipeline, then forwards to
the origin with correct `X-Forwarded-*` / `X-Real-IP` headers.

### Multi-site / host routing

One instance can protect several sites; the inbound `Host` picks the origin:

```json
"upstream": "http://127.0.0.1:3000",
"sites": [
  { "host": "shop.example.com", "upstream": "https://shop.vercel.app", "preserve_host": false },
  { "host": "app.example.com",  "upstream": "http://127.0.0.1:4000",   "preserve_host": true  }
]
```

**`preserve_host` is the key knob:**
- **Self-hosted / Dokploy / a local app** → `true` (the app expects its real domain).
- **Vercel / Netlify and similar platforms** → `false`. They route by `Host`
  and only recognise their own `*.vercel.app` name, so AggerShield must send
  that. (You still also set your custom domain inside the Vercel project.)

### HTTPS

```json
"tls": {
  "enabled": true,
  "https_listen": ":443",
  "http_listen": ":80",
  "redirect_http": true,
  "cert_file": "/etc/ssl/example.com.crt",
  "key_file": "/etc/ssl/example.com.key"
}
```

Use real certs in production (an OVH/Cloudflare **origin certificate**), or for
local testing set `"self_signed": true` and use `curl -k`.

**Automatic HTTPS (Let's Encrypt):** set `tls.auto_cert` and certificates are
obtained and renewed automatically — no cert files:

```json
"tls": {
  "enabled": true,
  "auto_cert": { "enabled": true, "domains": ["example.com"], "email": "you@example.com", "cache_dir": "./acme-cache" }
}
```

Site hosts are added to the allowlist automatically. The box must be reachable
from the internet on **:80** (ACME HTTP-01 challenge — served automatically)
and **:443**. Issued certs are cached so restarts don't re-request them.

### Deployment per platform

- **Dokploy / VPS / Docker (ideal):** run AggerShield as the public entry
  point (`:80`/`:443`) and forward to Dokploy's Traefik or your container.
  You own the entry point, so this is the strongest fit.
- **Vercel:** put your domain's DNS on the AggerShield VPS and route to
  `https://<project>.vercel.app` with `preserve_host:false`. You gain custom
  L7 control (rules, challenges, bans); note a single VPS can't out-scale
  Vercel's edge for raw volumetric, so for that, front AggerShield with
  Cloudflare/OVH too.
- **Behind Cloudflare/OVH (recommended for volumetric):**
  `Cloudflare → AggerShield → origin`. Cloudflare absorbs L3/L4 volume and
  provides TLS; AggerShield does the smart L7 logic. Put Cloudflare's IP
  ranges in `trusted_proxies` so the real visitor IP is honoured.

> ⚠️ **Reminder:** a single host can't absorb a volumetric L3/L4 flood — that
> saturates the uplink upstream of any software. AggerShield owns the L7 +
> connection layer; pair it with edge scrubbing for the volumetric layer.

## Try the demo

Three terminals (or build the binaries with `go build -o bin/ ./cmd/...`):

```bash
# 1) the protected backend
go run ./cmd/origin -addr :3000

# 2) AggerShield in front of it (challenges in "always" mode)
go run ./cmd/aggershield -config config.demo.json

# 3a) a "botnet": each request a unique IP, no JavaScript
go run ./cmd/flood -mode distributed -n 200 -c 20
#    => CHL: 200   (every request walled at the challenge; 0 reach origin)

# 3b) a real browser: solves the proof-of-work, then passes
go run ./cmd/flood -mode single -n 4 -ip 203.0.113.99 -solve
#    => 200: 4

# watch it live
curl http://127.0.0.1:8080/aggershield/stats
```

`cmd/flood` is a demo tool: it only targets a URL you control and simulates
source IPs via `X-Forwarded-For` (AggerShield must trust the loopback as a
proxy, as `config.demo.json` does).

## Minecraft server protection

Minecraft (Java) speaks its own TCP protocol, so generic proxies miss its
attacks — server-list-ping floods and bot-join floods. Enable the
protocol-aware proxy and point it at your server:

```json
"minecraft": {
  "enabled": true,
  "listen": ":25565",
  "upstream": "127.0.0.1:25566",
  "max_conns_per_ip": 8,
  "new_conns_per_sec": 5,
  "new_conns_burst": 10,
  "handshake_timeout": "5s",
  "ban_on_abuse": true
}
```

It parses the Minecraft handshake to drop malformed connections, rate-limits new
connections and caps per-IP concurrency, enforces a handshake timeout
(anti-slowloris), and **shares the same ban list as the HTTP guard** — an IP
banned anywhere is banned everywhere. Players then splice straight through to
your server. (Point your real MC server at `:25566` and players at `:25565`.)

## ML / anomaly detection (control plane)

A separate Python **control plane** (`detector/`) watches AggerShield's metrics
and drives mitigation — it never sits in the request hot path. The default
detector is **pure standard library** (no installs):

```bash
python detector/detector.py --token YOUR_ADMIN_TOKEN
```

It polls `/aggershield/stats`, learns an online baseline (EWMA + mean absolute
deviation) of request/block rates, and when it spots an anomaly it flips
AggerShield into under-attack mode (`POST /admin/mode?challenge=always`),
relaxing back to `adaptive` once traffic calms. A second backend loads a
trained **XGBoost / CICDDoS2019** model (the report's Section-8 approach) —
see [`detector/README.md`](detector/README.md) and `detector/train_model.py`.

Demonstrated end-to-end: a flood drove `req/s` from 0 → 2000, the detector
scored it an attack and set `challenge=always`, then auto-recovered to
`adaptive` when the flood stopped.

## Tests

```bash
go test ./...
```

Covered: rate-limit → ban → block sequence, allowlist immunity, ban
escalation, the challenge issue → solve → verify round-trip (incl. rejecting
forged signatures, lowered difficulty, and expired clearances), denylist,
bad-UA blocking, per-route rules (block/allow/challenge/rate-override, regex
and method matching, first-match-wins), and live hot-reload applying new rules.

## Roadmap

Done: the **L7 core** (rate limits, bans, conn caps, timeouts), the
**proof-of-work challenge** layer, **per-route rules + hot-reload + admin API**,
**HTTPS termination with multi-site host routing**, **automatic HTTPS
(ACME/Let's Encrypt)**, the **Minecraft protocol-aware proxy**, and the
**ML/anomaly control plane** (EWMA live + XGBoost/CICDDoS2019 training). Planned
next:

1. **CAPTCHA escalation** — when PoW alone isn't enough, escalate to a human check (hooks for hCaptcha/Turnstile).
2. **Behavioral fingerprinting** — JA3/JA4 TLS + HTTP/2 frame fingerprints to catch real-browser bots.
3. **Tarpitting** — hold malicious connections slow instead of cleanly rejecting (cost asymmetry).
4. **Upstream scrubbing integration** — OVH / Cloudflare / BGP blackhole APIs for the volumetric layer AggerShield can't absorb locally.

## License

Proprietary / source-available — see [LICENSE](LICENSE). You may read and
evaluate the code; production, commercial, or hosted-service use needs written
permission. (Swap in MIT/Apache if you decide to open-source it.)

## Disclaimer

AggerShield is a **defensive** tool for protecting infrastructure you own or are authorized to protect. It is not a load-testing or attack tool.
