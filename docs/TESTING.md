# AggerShield — Stress / Resilience Testing Guide

How to test AggerShield's strength against a (simulated) DDoS — safely, on
infrastructure **you own**, and how to read the results.

---

## 0. Rules of engagement (read first)

- **Only test infrastructure you own or are explicitly authorized to test.** Both
  the target and the load generator must be yours.
- **Don't route load through third-party / "free" proxies.** Those are machines
  you don't control (often compromised hosts/honeypots); using them is
  unauthorized and only serves to obscure traffic source — the defining trait of
  attack tooling. You don't need them: a proxy request and a spoofed
  `X-Forwarded-For` look identical to the layer you're testing.
- **Don't flood through Cloudflare** (`https://your-domain`). Cloudflare reads it
  as abuse, and it won't reflect AggerShield anyway (CF shapes it first). Test
  AggerShield's port **directly**.
- **Keep load bounded.** A few thousand requests proves the defenses fire. A
  sustained max-rate flood can trip your VPS provider's abuse detection
  (Oracle/DigitalOcean) and burn egress quota. The goal is *"does it filter?"*,
  not *"can I melt the box?"*.

---

## 1. What you're testing

| Defence | What triggers it | What you'll see |
|---|---|---|
| Per-IP rate limit | one source over its budget | `429`, then a ban |
| Escalating ban | repeat offender | `403` (longer each time) |
| **Global limiter** | total flood, even if each IP is "quiet" | `503` (shed) |
| **PoW challenge** | under pressure / always mode | `CHL` — bots that don't run JS never pass |
| Tarpit | any blocked request | the block response is *held* for `tarpit.delay` |
| Security monitor | sustained mitigation | an **attack event** in `/aggershield/events` |

## 2. The key trick: simulating a distributed botnet

A real botnet = many distinct source IPs. You reproduce that **without** real
proxies: AggerShield reads the client IP from `X-Forwarded-For` **only when the
peer is a trusted proxy**. So in a *test* config you set `trusted_proxies` to your
load-generator's IP, and the bundled `cmd/flood -mode distributed` stamps a unique
random `X-Forwarded-For` on every request → AggerShield sees thousands of distinct
"clients", exercising the exact code paths a real botnet hits.

> ⚠️ Only do this in a **dedicated load-test config**. Never trust arbitrary
> `X-Forwarded-For` in production — it would let anyone spoof their IP.

---

## 3. Method A — single-box local rig (fastest, zero network)

Everything on one box (`127.0.0.1`). Best for quickly proving the logic.

```bash
# build the load generator
cd /opt/AggerShield && go build -o /usr/local/bin/ags-flood ./cmd/flood

# a tiny backend + a load-test AggerShield in front of it
cat > /tmp/loadtest.json <<'JSON'
{
  "listen": ":8088",
  "upstream": "http://127.0.0.1:3001",
  "trusted_proxies": ["127.0.0.1/32"],
  "rate_limit": { "per_ip_rps": 5, "per_ip_burst": 5, "global_rps": 50, "global_burst": 50 },
  "challenge": { "enabled": true, "mode": "adaptive" },
  "monitor": { "sample_interval": "1s", "attack_threshold": 20, "exit_intervals": 3 }
}
JSON
python3 -m http.server 3001 >/dev/null 2>&1 &
aggershield -config /tmp/loadtest.json >/tmp/ags-loadtest.log 2>&1 &
sleep 2 && curl -s -o /dev/null -w "target up -> %{http_code}\n" http://127.0.0.1:8088/
```

Run the scenarios in §5, then clean up:
```bash
pkill -f "aggershield -config /tmp/loadtest.json"; pkill -f "http.server 3001"
```

---

## 4. Method B — two-VPS distributed test (real network)

Target = AggerShield box; load = a **second VPS you own**. This is what was run
against `159.65.24.241` (target) from `140.238.252.217` (load).

### 4.1 On the TARGET (AggerShield box)
```bash
cat > /etc/aggershield/loadtest.json <<'JSON'
{
  "listen": ":8088",
  "upstream": "http://127.0.0.1:3001",
  "trusted_proxies": ["<LOAD_VPS_IP>/32"],
  "rate_limit": { "per_ip_rps": 5, "per_ip_burst": 5, "global_rps": 100, "global_burst": 100 },
  "challenge": { "enabled": true, "mode": "adaptive" },
  "monitor": { "sample_interval": "1s", "attack_threshold": 20, "exit_intervals": 3 }
}
JSON
python3 -m http.server 3001 >/dev/null 2>&1 &
aggershield -config /etc/aggershield/loadtest.json >/tmp/ags-loadtest.log 2>&1 &
sleep 2 && curl -s -o /dev/null -w "target up -> %{http_code}\n" http://127.0.0.1:8088/
ufw allow from <LOAD_VPS_IP> to any port 8088 proto tcp comment 'loadtest'
```

### 4.2 On the LOAD VPS
```bash
curl -fsSLO https://go.dev/dl/go1.26.2.linux-amd64.tar.gz
rm -rf /usr/local/go && tar -C /usr/local -xzf go1.26.2.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
cd /opt && git clone https://github.com/k4ran909/AggerShield.git && cd AggerShield
go build -o /usr/local/bin/ags-flood ./cmd/flood
```

Then run §5 with `-url http://<TARGET_IP>:8088/`.

### 4.3 Tear down
```bash
# on the target:
pkill -f "aggershield -config /etc/aggershield/loadtest.json"; pkill -f "http.server 3001"
ufw delete allow from <LOAD_VPS_IP> to any port 8088 proto tcp
```

---

## 5. Scenarios

Replace `TARGET` with `127.0.0.1` (Method A) or `<TARGET_IP>` (Method B).

**Scenario 1 — one noisy IP (rate-limit → ban)**
```bash
ags-flood -url http://TARGET:8088/ -mode single -ip 203.0.113.7 -n 40 -c 1
```
Expect: a few `200` (burst) → `429` → `403` (banned).

**Scenario 2 — distributed botnet (the headline test)**
```bash
ags-flood -url http://TARGET:8088/ -mode distributed -n 5000 -c 100
```
Expect: mostly `CHL` (challenged — bots can't solve the PoW) and `503` (global
shed). **Very few / zero reach the backend.**

**Scenario 3 — a real browser still gets through**
```bash
ags-flood -url http://TARGET:8088/ -mode single -ip 198.51.100.9 -n 4 -solve
```
Expect: `200` — `-solve` makes the tool compute the proof-of-work like a browser,
so legitimate users pass while the botnet is filtered.

---

## 6. Reading the results

The flood tool prints a status-code histogram:

```
Flood complete: mode=distributed requests=5000 ...
Status code distribution:
  CHL : 4700     ← challenged, never reached your app
  503 : 295      ← shed by the global limiter
  200 : 5        ← a handful slipped through before the challenge engaged
```

On the AggerShield box, inspect what it recorded:
```bash
curl -s http://127.0.0.1:8088/aggershield/stats     | python3 -m json.tool
curl -s http://127.0.0.1:8088/aggershield/events    | python3 -m json.tool
```

- `stats`: `challenged`, `rate_limited_per_ip`, `rate_limited_global`, `bans_issued`.
- `events`: an **attack event** with `start`/`end`, `peak_reqs`, and total mitigated.
- Live dashboard (browser): `http://TARGET:8088/aggershield/security` — state badge
  flips to **UNDER ATTACK**, traffic charts spike, the event appears in the log.

> Note: the load-test config above does **not** set `protect_telemetry`, so
> `/stats`, `/events`, `/security` are open for convenience during testing. The
> production config sets `protect_telemetry: true` (token required).

### What "good" looks like
- Distributed flood → **near-100% of requests are `CHL`/`503`**, near-zero reach
  the backend.
- `-solve` requests → `200` (real users unharmed).
- An attack event is logged with a realistic peak rate.
- Verified example: a 12,000-request distributed run shed **11,845** at the global
  limiter and auto-logged the event; a 200-request no-JS botnet run was **100%
  challenged (0 reached origin)**.

---

## 7. Throughput numbers (optional)

To measure raw capacity rather than filtering, use a standard tool against a
permissive config (high limits, challenge off):
```bash
apt-get install -y wrk
wrk -t4 -c200 -d30s http://TARGET:8088/
```
For reference, the guard's hot path benchmarks at ~**522 ns/op (~1.9M req/s per
core)**: `go test -bench=BenchmarkGuardAllowPath ./internal/guard`.

---

## 8. Common gotchas

- **`through AggerShield -> 000` / nothing happens:** the agent isn't running.
  Usual cause is a **full disk** (`df -h /`) — clean caches (see DEPLOYMENT §7).
- **`cmd/flood` hits the wrong place:** it defaults to `-url http://127.0.0.1:8080/`.
  Always pass `-url` explicitly.
- **Distributed mode bans your one real IP instead of shedding:** the target's
  `trusted_proxies` doesn't include your load box, so `X-Forwarded-For` is ignored
  and every request looks like the same IP. Add the load IP to `trusted_proxies`.
- **Don't reuse the production config for load tests** — its `trusted_proxies` is
  Cloudflare's ranges, not your load box.
