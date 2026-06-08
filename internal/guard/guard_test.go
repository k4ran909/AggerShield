package guard

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"aggershield/internal/banlist"
	"aggershield/internal/challenge"
	"aggershield/internal/config"
	"aggershield/internal/connlimit"
	"aggershield/internal/metrics"
	"aggershield/internal/policy"
)

func quietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// buildGuard wires a Guard from a config, with challenges optionally enabled.
func buildGuard(t *testing.T, cfg *config.Config, allowlist []string, withChallenge bool) *Guard {
	t.Helper()
	cfg.RateLimit.GlobalRPS, cfg.RateLimit.GlobalBurst = 1e9, 1e9 // effectively unlimited
	if cfg.Ban.MaxEntries == 0 {
		cfg.Ban.MaxEntries = 1000
	}
	if cfg.Block.Status == 0 {
		cfg.Block.Status, cfg.Block.Message = 403, "Forbidden"
	}
	bans := banlist.New(time.Minute, time.Hour, 2.0, time.Hour, cfg.Ban.MaxEntries, allowlist)
	t.Cleanup(bans.Close)

	snap, err := policy.Build(cfg)
	if err != nil {
		t.Fatalf("policy.Build: %v", err)
	}
	t.Cleanup(snap.Close)

	var chal *challenge.Manager
	if withChallenge {
		chal = challenge.New("secret", 10, time.Minute)
	}
	return New(Deps{
		Bans: bans, Challenge: chal, Conns: connlimit.New(1000),
		Metrics: metrics.New(), Log: quietLog(),
	}, snap)
}

func send(t *testing.T, h http.Handler, method, path, ip, ua string) int {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	req.RemoteAddr = ip + ":1234"
	if ua != "" {
		req.Header.Set("User-Agent", ua)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
}

func TestRateLimitTripsThenBans(t *testing.T) {
	cfg := &config.Config{Upstream: "http://x"}
	cfg.RateLimit.PerIPRPS, cfg.RateLimit.PerIPBurst = 0.0001, 3
	cfg.Connection.MaxBodyBytes = 1 << 20
	g := buildGuard(t, cfg, nil, false)
	h := g.Wrap(okHandler())

	var got []int
	for i := 0; i < 6; i++ {
		got = append(got, send(t, h, http.MethodGet, "/", "203.0.113.5", ""))
	}
	want := []int{200, 200, 200, http.StatusTooManyRequests, http.StatusForbidden, http.StatusForbidden}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("request %d: got %d want %d (seq %v)", i, got[i], want[i], got)
		}
	}
}

func TestAllowlistNeverBanned(t *testing.T) {
	cfg := &config.Config{Upstream: "http://x"}
	cfg.RateLimit.PerIPRPS, cfg.RateLimit.PerIPBurst = 0.0001, 1
	g := buildGuard(t, cfg, []string{"198.51.100.7"}, false)
	h := g.Wrap(okHandler())
	for i := 0; i < 50; i++ {
		if code := send(t, h, http.MethodGet, "/", "198.51.100.7", ""); code != http.StatusOK {
			t.Fatalf("allowlisted IP got %d on request %d", code, i)
		}
	}
}

func TestDenylistBlocked(t *testing.T) {
	cfg := &config.Config{Upstream: "http://x", Denylist: []string{"10.0.0.0/8"}}
	cfg.RateLimit.PerIPRPS, cfg.RateLimit.PerIPBurst = 1000, 1000
	g := buildGuard(t, cfg, nil, false)
	h := g.Wrap(okHandler())
	if code := send(t, h, http.MethodGet, "/", "10.1.2.3", ""); code != http.StatusForbidden {
		t.Fatalf("denylisted IP got %d, want 403", code)
	}
	if code := send(t, h, http.MethodGet, "/", "192.0.2.1", ""); code != http.StatusOK {
		t.Fatalf("non-denylisted IP got %d, want 200", code)
	}
}

func TestRuleBlockAndAllow(t *testing.T) {
	cfg := &config.Config{Upstream: "http://x"}
	cfg.RateLimit.PerIPRPS, cfg.RateLimit.PerIPBurst = 1000, 1000
	cfg.Rules = []config.Rule{
		{Name: "block-admin", PathPrefix: "/wp-admin", Action: "block"},
		{Name: "allow-health", PathPrefix: "/healthz", Action: "allow"},
	}
	g := buildGuard(t, cfg, nil, false)
	h := g.Wrap(okHandler())

	if code := send(t, h, http.MethodGet, "/wp-admin/x", "203.0.113.9", ""); code != http.StatusForbidden {
		t.Fatalf("blocked route got %d, want 403", code)
	}
	if code := send(t, h, http.MethodGet, "/healthz", "203.0.113.9", ""); code != http.StatusOK {
		t.Fatalf("allowed route got %d, want 200", code)
	}
}

func TestRuleForcesChallenge(t *testing.T) {
	cfg := &config.Config{Upstream: "http://x"}
	cfg.RateLimit.PerIPRPS, cfg.RateLimit.PerIPBurst = 1000, 1000
	cfg.Rules = []config.Rule{{Name: "protect-login", PathPrefix: "/login", Action: "challenge"}}
	g := buildGuard(t, cfg, nil, true)
	h := g.Wrap(okHandler())

	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	req.RemoteAddr = "203.0.113.20:1234"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Header().Get(challenge.HeaderChallenge) != "1" {
		t.Fatalf("expected a challenge on /login, got status %d", rec.Code)
	}
	// A non-challenged route still passes.
	if code := send(t, h, http.MethodGet, "/", "203.0.113.20", ""); code != http.StatusOK {
		t.Fatalf("non-challenge route got %d, want 200", code)
	}
}

func TestBadUserAgentBlocked(t *testing.T) {
	cfg := &config.Config{Upstream: "http://x", BadUserAgents: []string{"evilbot"}}
	cfg.RateLimit.PerIPRPS, cfg.RateLimit.PerIPBurst = 1000, 1000
	g := buildGuard(t, cfg, nil, false)
	h := g.Wrap(okHandler())
	if code := send(t, h, http.MethodGet, "/", "203.0.113.30", "Mozilla/5.0 EvilBot/1.0"); code != http.StatusForbidden {
		t.Fatalf("bad UA got %d, want 403", code)
	}
	if code := send(t, h, http.MethodGet, "/", "203.0.113.31", "Mozilla/5.0"); code != http.StatusOK {
		t.Fatalf("good UA got %d, want 200", code)
	}
}

func TestReloadAppliesNewRules(t *testing.T) {
	cfg := &config.Config{Upstream: "http://x"}
	cfg.RateLimit.PerIPRPS, cfg.RateLimit.PerIPBurst = 1000, 1000
	g := buildGuard(t, cfg, nil, false)
	h := g.Wrap(okHandler())

	if code := send(t, h, http.MethodGet, "/secret", "203.0.113.40", ""); code != http.StatusOK {
		t.Fatalf("before reload got %d, want 200", code)
	}
	// Hot-reload with a blocking rule.
	newCfg := &config.Config{Upstream: "http://x"}
	newCfg.RateLimit.GlobalRPS, newCfg.RateLimit.GlobalBurst = 1e9, 1e9
	newCfg.RateLimit.PerIPRPS, newCfg.RateLimit.PerIPBurst = 1000, 1000
	newCfg.Ban.MaxEntries = 1000
	newCfg.Block.Status, newCfg.Block.Message = 403, "Forbidden"
	newCfg.Rules = []config.Rule{{Name: "block-secret", PathPrefix: "/secret", Action: "block"}}
	if err := g.Reload(newCfg); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if code := send(t, h, http.MethodGet, "/secret", "203.0.113.40", ""); code != http.StatusForbidden {
		t.Fatalf("after reload got %d, want 403", code)
	}
}

func TestDryRunDoesNotBlock(t *testing.T) {
	cfg := &config.Config{Upstream: "http://x", Denylist: []string{"10.0.0.0/8"}, DryRun: true}
	cfg.RateLimit.PerIPRPS, cfg.RateLimit.PerIPBurst = 0.0001, 1
	cfg.Rules = []config.Rule{{Name: "block-admin", PathPrefix: "/wp-admin", Action: "block"}}
	g := buildGuard(t, cfg, nil, false)
	h := g.Wrap(okHandler())

	// All of these WOULD block in enforce mode, but dry-run lets them through.
	cases := []struct{ path, ip string }{
		{"/wp-admin", "203.0.113.1"}, // rule block
		{"/", "10.1.2.3"},            // denylist
		{"/", "203.0.113.2"},         // first request fine
		{"/", "203.0.113.2"},         // second trips rate limit (burst 1) -> would ban
	}
	for i, c := range cases {
		if code := send(t, h, http.MethodGet, c.path, c.ip, ""); code != http.StatusOK {
			t.Fatalf("dry-run case %d (%s %s) got %d, want 200 (nothing should be blocked)", i, c.path, c.ip, code)
		}
	}
}

func TestChallengeSkipsNonBrowserByDefault(t *testing.T) {
	cfg := &config.Config{Upstream: "http://x"}
	cfg.RateLimit.PerIPRPS, cfg.RateLimit.PerIPBurst = 1000, 1000
	cfg.Challenge.Enabled, cfg.Challenge.Mode = true, "always"
	// ChallengeNonBrowser defaults to false => html-only.
	g := buildGuard(t, cfg, nil, true)
	h := g.Wrap(okHandler())

	// No Accept: text/html (e.g. an API/XHR client) -> NOT challenged, passes.
	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	req.RemoteAddr = "203.0.113.10:1234"
	req.Header.Set("Accept", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Header().Get(challenge.HeaderChallenge) == "1" {
		t.Fatal("non-browser (JSON) request should not be challenged by default")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("API client got %d, want 200", rec.Code)
	}

	// A browser navigation (Accept: text/html) IS challenged.
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.11:1234"
	req.Header.Set("Accept", "text/html")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Header().Get(challenge.HeaderChallenge) != "1" {
		t.Fatalf("browser request should be challenged, got status %d", rec.Code)
	}
}

func TestBanEscalation(t *testing.T) {
	bans := banlist.New(time.Second, time.Hour, 2.0, time.Hour, 1000, nil)
	defer bans.Close()
	d1 := bans.Ban("192.0.2.1")
	d2 := bans.Ban("192.0.2.1")
	d3 := bans.Ban("192.0.2.1")
	if !(d1 < d2 && d2 < d3) {
		t.Fatalf("expected escalating ban durations, got %v, %v, %v", d1, d2, d3)
	}
}
