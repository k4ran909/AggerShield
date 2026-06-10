// Package guard composes AggerShield's defence pipeline into one
// http.Handler that wraps the upstream proxy.
//
// The guard reads its policy from an atomically-swappable *policy.Snapshot,
// so configuration can be hot-reloaded with no locks on the request path:
// Reload() builds a new snapshot, updates the long-lived stateful components
// (ban table, challenge manager, connection limiter) via their setters, swaps
// the pointer, and closes the old snapshot's limiters.
//
// Request pipeline (cheapest checks first, so attack traffic is rejected
// before it costs us real work):
//
//  1. Resolve the true client IP (peer address, or trusted XFF).
//  2. Allowlist     -> always pass.
//  3. Denylist      -> always block.
//  4. Per-route rule -> allow / block / force-challenge / default.
//  5. Ban check     -> already-banned IPs are dropped.
//  6. Bad User-Agent -> block known bad bots.
//  7. Challenge gate -> PoW unless cleared (always, or adaptive under load).
//  8. Global rate limit -> aggregate ceiling (distributed-flood defence).
//  9. Per-IP rate limit -> over-budget source earns an escalating ban.
//
// 10. Per-IP concurrency cap -> blunts slow/connection-exhaustion attacks.
// 11. Body size cap -> bounds memory per request.
package guard

import (
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"aggershield/internal/banlist"
	"aggershield/internal/challenge"
	"aggershield/internal/config"
	"aggershield/internal/connlimit"
	"aggershield/internal/fingerprint"
	"aggershield/internal/metrics"
	"aggershield/internal/netutil"
	"aggershield/internal/policy"
	"aggershield/internal/rules"
)

// Guard holds long-lived stateful components plus the hot-swappable policy.
type Guard struct {
	// Long-lived (survive reloads via setters).
	bans    *banlist.Store
	chal    *challenge.Manager
	conns   *connlimit.Limiter
	metrics *metrics.Metrics
	log     *slog.Logger

	// snap is the current policy snapshot, swapped atomically on reload.
	snap atomic.Pointer[policy.Snapshot]

	// Licensing (fail-closed). When licenseEnforced is true and licensed is
	// false, the proxy refuses to serve (503). Both are no-ops when the agent
	// runs unlicensed (standalone mode).
	licenseEnforced bool
	licensed        atomic.Bool

	// tarpit is a bounded set of slots for holding blocked connections open.
	// Bounding it stops the tarpit from exhausting our own file descriptors.
	tarpit chan struct{}
}

// Deps bundles the long-lived components.
type Deps struct {
	Bans      *banlist.Store
	Challenge *challenge.Manager
	Conns     *connlimit.Limiter
	Metrics   *metrics.Metrics
	Log       *slog.Logger
	TarpitMax int // max simultaneously tarpitted connections
}

// New builds a Guard with an initial policy snapshot.
func New(d Deps, snap *policy.Snapshot) *Guard {
	max := d.TarpitMax
	if max <= 0 {
		max = 4096
	}
	g := &Guard{
		bans:    d.Bans,
		chal:    d.Challenge,
		conns:   d.Conns,
		metrics: d.Metrics,
		log:     d.Log,
		tarpit:  make(chan struct{}, max),
	}
	g.snap.Store(snap)
	return g
}

// Reload builds a new snapshot from cfg, updates the long-lived components,
// swaps the snapshot in, and closes the previous one. It is safe to call
// concurrently with live traffic.
func (g *Guard) Reload(cfg *config.Config) error {
	newSnap, err := policy.Build(cfg)
	if err != nil {
		return err
	}
	// Update long-lived components that aren't part of the snapshot.
	g.bans.SetAllowlist(cfg.Allowlist)
	g.bans.SetParams(cfg.Ban.BaseDuration.Std(), cfg.Ban.MaxDuration.Std(), cfg.Ban.EscalationFactor, cfg.Ban.MaxEntries)
	g.conns.SetMax(cfg.Connection.MaxPerIP)
	if g.chal != nil {
		g.chal.SetParams(cfg.Challenge.DifficultyBits, cfg.Challenge.ClearanceTTL.Std())
	}

	old := g.snap.Swap(newSnap)
	old.Close() // stop the old snapshot's limiter goroutines
	g.log.Info("policy reloaded",
		"rules", len(cfg.Rules), "challenge", cfg.Challenge.Enabled, "challenge_mode", cfg.Challenge.Mode)
	return nil
}

// EnforceLicense turns on the fail-closed license gate. Until SetLicensed(true)
// is called, proxied traffic is refused with 503.
func (g *Guard) EnforceLicense() { g.licenseEnforced = true }

// SetLicensed updates the live license state (called by the license agent on
// each validate/heartbeat result).
func (g *Guard) SetLicensed(ok bool) { g.licensed.Store(ok) }

// SetChallengeMode flips challenge mode at runtime — e.g. an external detector
// switching to "always" (under-attack mode) when it spots an anomaly, then
// back to "adaptive" when it clears. It shallow-copies the current snapshot
// (sharing limiters/rules), so it must NOT close the previous snapshot.
func (g *Guard) SetChallengeMode(always bool) {
	old := g.snap.Load()
	cp := *old
	cp.ChallengeAlways = always
	cp.ChallengeEnabled = true
	g.snap.Store(&cp)
	g.log.Info("challenge mode set", "always", always)
}

// Wrap returns next guarded by the full pipeline.
func (g *Guard) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s := g.snap.Load()
		g.metrics.Total.Add(1)

		// 1. License gate (fail-closed). A revoked/unconfirmed key stops the
		// proxy from serving — this is the operator's central kill switch.
		if g.licenseEnforced && !g.licensed.Load() {
			w.Header().Set("Retry-After", "60")
			http.Error(w, "Service unavailable (unlicensed)", http.StatusServiceUnavailable)
			return
		}

		ip := netutil.ClientIP(r, s.Trusted)
		// Make the resolved client IP available to the proxy so it can set
		// X-Real-IP / X-Forwarded-For for the origin (correct even if we sit
		// behind Cloudflare/OVH).
		r = r.WithContext(netutil.WithClientIP(r.Context(), ip))

		// 2. Allowlist short-circuit.
		if g.bans.IsAllowed(ip) {
			g.serve(s, next, w, r)
			return
		}

		// 3. Static denylist.
		if netutil.Contains(s.DenyNets, ip) {
			if g.enforce(s, "denylist", ip, r) {
				g.block(s, w, r)
				return
			}
		}

		// 3a. TLS fingerprint blocklist (JA3/JA4). Catches automated clients
		// whose TLS stack is on the blocklist regardless of their User-Agent.
		if s.FingerprintEnabled && len(s.FingerprintBlock) > 0 {
			if ja3, ja4, ok := fingerprint.FromContext(r.Context()); ok &&
				(s.FingerprintBlock[ja3] || s.FingerprintBlock[ja4]) {
				if g.enforce(s, "tls-fingerprint", ip, r) {
					g.metrics.FpBlocked.Add(1)
					g.block(s, w, r)
					return
				}
			}
		}

		// 4. Per-route rule.
		decision := s.Rules.Match(r)
		switch decision.Action {
		case rules.ActionAllow:
			g.serve(s, next, w, r)
			return
		case rules.ActionBlock:
			if g.enforce(s, "rule:"+decision.Name, ip, r) {
				g.block(s, w, r)
				return
			}
		}

		// 5. Already banned?
		if g.bans.IsBanned(ip) {
			if g.enforce(s, "banned", ip, r) {
				g.metrics.BlockedBanned.Add(1)
				g.block(s, w, r)
				return
			}
		}

		// 6. Bad User-Agent filter.
		if len(s.BadUAs) > 0 {
			ua := strings.ToLower(r.UserAgent())
			for _, bad := range s.BadUAs {
				if bad != "" && strings.Contains(ua, bad) {
					if g.enforce(s, "bad-user-agent", ip, r) {
						g.block(s, w, r)
						return
					}
					break
				}
			}
		}

		// 7. Challenge gate (distributed-botnet defence). A client without
		// valid clearance must solve a proof-of-work. Forced by a rule, or by
		// "always" mode, or by "adaptive" mode when the global limiter is
		// under pressure. By default only browser navigations (Accept:
		// text/html) are challenged, so APIs/mobile apps/webhooks are spared.
		if g.chal != nil && !g.chal.HasClearance(r) {
			force := decision.Action == rules.ActionChallenge
			auto := s.ChallengeEnabled && (s.ChallengeAlways || s.Global.Remaining() < s.PressureThreshold)
			browserOK := force || s.ChallengeNonBrowser || acceptsHTML(r)
			if (force || auto) && browserOK {
				g.metrics.Challenged.Add(1)
				if g.enforce(s, "challenge", ip, r) {
					g.chal.Serve(w, r)
					return
				}
			}
		}

		// 8. Global ceiling (distributed-flood defence). Shed, do not ban.
		if !s.Global.Allow() {
			g.metrics.RateLimitedGl.Add(1)
			if g.enforce(s, "global-limit", ip, r) {
				w.Header().Set("Retry-After", "1")
				http.Error(w, "Service busy", http.StatusServiceUnavailable)
				return
			}
		}

		// 9. Per-IP budget (route override if the matched rule set one).
		limiter := s.DefaultPerIP
		if decision.Limiter != nil {
			limiter = decision.Limiter
		}
		if !limiter.Allow(ip) {
			g.metrics.RateLimitedIP.Add(1)
			if g.enforce(s, "rate-limit", ip, r) {
				dur := g.bans.Ban(ip)
				g.metrics.BansIssued.Add(1)
				g.log.Warn("rate limit exceeded; IP banned",
					"ip", ip, "ban_duration", dur.String(), "path", r.URL.Path, "rule", decision.Name)
				w.Header().Set("Retry-After", "1")
				http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
				return
			}
		}

		// 10. Per-IP concurrency cap (slow-attack defence).
		release, ok := g.conns.Acquire(ip)
		if !ok {
			g.metrics.ConnRejected.Add(1)
			if g.enforce(s, "conn-cap", ip, r) {
				http.Error(w, "Too many concurrent connections", http.StatusTooManyRequests)
				return
			}
		}
		if release != nil {
			defer release()
		}

		g.metrics.Allowed.Add(1)
		g.serve(s, next, w, r)
	})
}

// enforce reports whether a would-be denial should actually be enforced. In
// dry-run mode it records and logs the decision but returns false, so the
// request is allowed through untouched — letting operators validate config
// against real traffic without affecting users.
func (g *Guard) enforce(s *policy.Snapshot, reason, ip string, r *http.Request) bool {
	if s.DryRun {
		g.metrics.WouldBlock.Add(1)
		g.log.Info("dry-run: would act", "reason", reason, "ip", ip,
			"method", r.Method, "host", r.Host, "path", r.URL.Path)
		return false
	}
	return true
}

// acceptsHTML reports whether the request looks like a browser navigation.
func acceptsHTML(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}

// block writes the configured block response. When tarpitting is enabled and a
// slot is free, it first holds the connection open for TarpitDelay (or until
// the client disconnects / the request is cancelled), wasting the attacker's
// resources. If no slot is free it blocks immediately to protect our own fds.
func (g *Guard) block(s *policy.Snapshot, w http.ResponseWriter, r *http.Request) {
	if s.TarpitEnabled && s.TarpitDelay > 0 {
		select {
		case g.tarpit <- struct{}{}:
			g.metrics.Tarpitted.Add(1)
			t := time.NewTimer(s.TarpitDelay)
			select {
			case <-t.C:
			case <-r.Context().Done():
			}
			t.Stop()
			<-g.tarpit
		default:
			// tarpit full — fall through and block immediately
		}
	}
	http.Error(w, s.BlockMessage, s.BlockStatus)
}

func (g *Guard) serve(s *policy.Snapshot, next http.Handler, w http.ResponseWriter, r *http.Request) {
	// 11. Bound request body size to protect upstream memory.
	if s.MaxBodyBytes > 0 && r.Body != nil {
		r.Body = http.MaxBytesReader(w, r.Body, s.MaxBodyBytes)
	}
	next.ServeHTTP(w, r)
}
