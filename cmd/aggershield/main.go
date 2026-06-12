// Command aggershield is a cross-platform L7 reverse proxy that shields a
// backend (web app, ecommerce, game-server web panel, ...) from
// application-layer abuse: HTTP floods, slow attacks, and noisy sources.
//
// Configuration is fully customisable (per-route rules, denylist, custom
// block responses, challenge tuning, ...) and hot-reloadable: change the
// config file and either POST /aggershield/admin/reload or enable
// watch_interval to apply changes with no restart.
//
// Scope note: a host-based L7 proxy CANNOT absorb volumetric L3/L4 floods
// (those saturate your uplink before any software sees them). Pair this with
// upstream scrubbing (OVH/Cloudflare/BGP) for volumetric protection.
package main

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"flag"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"aggershield/internal/admin"
	"aggershield/internal/banlist"
	"aggershield/internal/challenge"
	"aggershield/internal/config"
	"aggershield/internal/connlimit"
	"aggershield/internal/fingerprint"
	"aggershield/internal/guard"
	"aggershield/internal/license"
	"aggershield/internal/mcproxy"
	"aggershield/internal/metrics"
	"aggershield/internal/policy"
	"aggershield/internal/proxy"
	"aggershield/internal/scrubber"
	"aggershield/internal/secmon"
	"aggershield/internal/tlsutil"
)

func main() {
	cfgPath := flag.String("config", "config.json", "path to config file")
	flag.Parse()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		slog.Error("load config", "err", err)
		os.Exit(1)
	}

	log := newLogger(cfg.Log)

	// Long-lived stateful components (survive hot-reloads via setters).
	bans := banlist.New(
		cfg.Ban.BaseDuration.Std(), cfg.Ban.MaxDuration.Std(),
		cfg.Ban.EscalationFactor, cfg.Ban.SweepInterval.Std(),
		cfg.Ban.MaxEntries, cfg.Allowlist,
	)
	defer bans.Close()
	if cfg.Ban.PersistPath != "" {
		if err := bans.EnablePersistence(cfg.Ban.PersistPath, 30*time.Second); err != nil {
			log.Error("ban persistence (continuing without it)", "err", err)
		} else {
			log.Info("ban persistence enabled", "path", cfg.Ban.PersistPath)
		}
	}
	conns := connlimit.New(cfg.Connection.MaxPerIP)
	mx := metrics.New()

	// Always-on security monitor: per-interval traffic time-series + automatic
	// attack-event detection (behind the /aggershield/security dashboard).
	mon := secmon.New(cfg.Monitor.SampleInterval.Std(), cfg.Monitor.Retain,
		cfg.Monitor.AttackThreshold, cfg.Monitor.ExitIntervals,
		func() secmon.Counters {
			return secmon.Counters{
				Total:   mx.Total.Load(),
				Allowed: mx.Allowed.Load(),
				Blocked: mx.BlockedBanned.Load() + mx.RateLimitedIP.Load() +
					mx.RateLimitedGl.Load() + mx.ConnRejected.Load() + mx.FpBlocked.Load(),
				Challenged: mx.Challenged.Load(),
				Bans:       mx.BansIssued.Load(),
			}
		})
	go mon.Run()
	defer mon.Close()
	// Always build the challenge manager; whether it's used is a policy flag,
	// so toggling challenge.enabled on reload Just Works.
	chal := challenge.New(cfg.Challenge.Secret, cfg.Challenge.DifficultyBits, cfg.Challenge.ClearanceTTL.Std())

	snap, err := policy.Build(cfg)
	if err != nil {
		log.Error("build policy", "err", err)
		os.Exit(1)
	}

	router, err := proxy.New(cfg, log)
	if err != nil {
		log.Error("build proxy", "err", err)
		os.Exit(1)
	}

	g := guard.New(guard.Deps{
		Bans: bans, Challenge: chal, Conns: conns, Metrics: mx, Log: log,
		TarpitMax: cfg.Tarpit.MaxConcurrent,
	}, snap)

	// currentCfg holds the effective config for the admin /config endpoint and
	// is replaced on each successful reload.
	var cfgMu sync.RWMutex
	currentCfg := cfg
	reload := func() (*config.Config, error) {
		nc, err := config.Load(*cfgPath)
		if err != nil {
			return nil, err
		}
		if err := g.Reload(nc); err != nil {
			return nil, err
		}
		cfgMu.Lock()
		currentCfg = nc
		cfgMu.Unlock()
		return nc, nil
	}
	snapshotCfg := func() *config.Config {
		cfgMu.RLock()
		defer cfgMu.RUnlock()
		return currentCfg
	}

	// Optional upstream/edge scrubber (engaged when under a volumetric attack).
	scrubBackend := scrubber.New(cfg.Scrubber, log)
	scrubFn := func(engage bool, reason string) error {
		if scrubBackend == nil {
			return errors.New("scrubber not configured")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		mx.ScrubActions.Add(1)
		var err error
		if engage {
			err = scrubBackend.Engage(ctx, reason)
		} else {
			err = scrubBackend.Disengage(ctx)
		}
		if err != nil {
			return err
		}
		if engage {
			mx.ScrubEngaged.Store(1)
		} else {
			mx.ScrubEngaged.Store(0)
		}
		log.Info("upstream scrubber", "provider", scrubBackend.Name(), "engaged", engage, "reason", reason)
		return nil
	}

	// Optional licensing: validate the key with the control plane and report
	// telemetry. Fail-closed enforcement is handled inside the guard.
	licCtx, licCancel := context.WithCancel(context.Background())
	defer licCancel()
	if cfg.License.Enabled {
		if cfg.License.FailOpen {
			g.SetLicensed(true) // never block on licensing
		} else {
			g.EnforceLicense() // blocks traffic until licensed
		}
		go runLicenseAgent(licCtx, cfg, g, bans, mx, log)
	}

	mux := http.NewServeMux()
	// Read-only telemetry endpoints. Optionally gated behind the admin token so
	// they aren't world-readable when AggerShield faces the internet.
	gate := func(h http.HandlerFunc) http.HandlerFunc { return h }
	if cfg.Admin.ProtectTelemetry && cfg.Admin.Token != "" {
		gate = func(h http.HandlerFunc) http.HandlerFunc { return telemetryGate(cfg.Admin.Token, h) }
		log.Info("telemetry endpoints require the admin token (header X-AggerShield-Token or ?token=)")
	}
	mux.HandleFunc("/aggershield/stats", gate(mx.Handler(bans.Count)))
	mux.HandleFunc("/metrics", gate(mx.Prometheus(bans.Count)))
	mux.HandleFunc("/aggershield/security", gate(mon.DashboardHandler()))
	mux.HandleFunc("/aggershield/timeseries", gate(mon.SamplesHandler()))
	mux.HandleFunc("/aggershield/events", gate(mon.EventsHandler()))
	mux.HandleFunc("/aggershield/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	if cfg.Admin.Enabled {
		admin.New(cfg.Admin.Token, *cfgPath, bans, reload, snapshotCfg, g.SetChallengeMode, scrubFn).Register(mux)
		log.Info("admin API enabled", "routes", "/aggershield/admin/{bans,config,ban,unban,reload,mode,scrub}")
	}
	mux.Handle("/", g.Wrap(router))

	srv := &http.Server{
		Handler: mux,
		// Server timeouts are the front line against slow attacks. They are
		// applied at listener creation and so are NOT hot-reloadable.
		ReadHeaderTimeout: cfg.Connection.ReadHeaderTimeout.Std(),
		ReadTimeout:       cfg.Connection.ReadTimeout.Std(),
		WriteTimeout:      cfg.Connection.WriteTimeout.Std(),
		IdleTimeout:       cfg.Connection.IdleTimeout.Std(),
		MaxHeaderBytes:    cfg.Connection.MaxHeaderBytes,
	}

	// Optional config file watcher for hands-off hot-reload.
	stopWatch := make(chan struct{})
	if cfg.WatchInterval.Std() > 0 {
		go watchConfig(*cfgPath, cfg.WatchInterval.Std(), reload, log, stopWatch)
	}

	// Optional Minecraft protocol-aware proxy (shares the ban store).
	mcCtx, mcCancel := context.WithCancel(context.Background())
	defer mcCancel()
	if cfg.Minecraft.Enabled {
		mc := mcproxy.New(cfg.Minecraft, bans, mx, log)
		go func() {
			if err := mc.ListenAndServe(mcCtx); err != nil {
				log.Error("minecraft proxy", "err", err)
			}
		}()
	}

	// An optional HTTP server: either a plain listener, or (with TLS) a small
	// redirect-to-HTTPS server.
	var redirectSrv *http.Server

	if cfg.TLS.Enabled {
		// TLS fingerprinting (JA3/JA4) only works when we terminate TLS.
		var chiHook func(*tls.ClientHelloInfo)
		if cfg.Fingerprint.Enabled {
			fp := fingerprint.New()
			chiHook = fp.Observe
			srv.ConnContext = fp.ConnContext
			srv.ConnState = fp.ConnState
			log.Info("TLS fingerprinting enabled (JA3/JA4)")
		}
		tlsCfg, acmeMgr, err := tlsutil.Build(cfg.TLS, siteHosts(cfg), chiHook)
		if err != nil {
			log.Error("tls", "err", err)
			os.Exit(1)
		}
		srv.Addr = cfg.TLS.HTTPSListen
		srv.TLSConfig = tlsCfg

		// The HTTP listener is needed when redirecting, and ALWAYS when ACME is
		// active (Let's Encrypt validates via an HTTP-01 challenge on :80).
		var httpHandler http.Handler
		if cfg.TLS.RedirectHTTP {
			httpHandler = redirectHandler(cfg.TLS.HTTPSListen)
		}
		if acmeMgr != nil {
			// Serve ACME challenges; fall back to the redirect (or 404).
			httpHandler = acmeMgr.HTTPHandler(httpHandler)
			log.Info("ACME auto-HTTPS enabled (Let's Encrypt)", "cache", cfg.TLS.AutoCert.CacheDir)
		}
		if httpHandler != nil {
			redirectSrv = &http.Server{
				Addr:              cfg.TLS.HTTPListen,
				Handler:           httpHandler,
				ReadHeaderTimeout: cfg.Connection.ReadHeaderTimeout.Std(),
			}
			go func() {
				if err := redirectSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
					log.Error("http redirect/acme server", "err", err)
				}
			}()
		}
		go func() {
			log.Info("AggerShield listening (HTTPS)",
				"https", cfg.TLS.HTTPSListen, "self_signed", cfg.TLS.SelfSigned,
				"sites", len(cfg.Sites), "rules", len(cfg.Rules),
				"challenge", cfg.Challenge.Enabled, "admin", cfg.Admin.Enabled)
			if err := srv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				log.Error("https server", "err", err)
				os.Exit(1)
			}
		}()
	} else {
		srv.Addr = cfg.Listen
		go func() {
			log.Info("AggerShield listening (HTTP)",
				"listen", cfg.Listen, "upstream", cfg.Upstream, "sites", len(cfg.Sites),
				"per_ip_rps", cfg.RateLimit.PerIPRPS, "global_rps", cfg.RateLimit.GlobalRPS,
				"rules", len(cfg.Rules), "challenge", cfg.Challenge.Enabled,
				"admin", cfg.Admin.Enabled, "watch", cfg.WatchInterval.Std().String())
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Error("server", "err", err)
				os.Exit(1)
			}
		}()
	}

	// Graceful shutdown; SIGHUP triggers a hot-reload.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	for {
		s := <-sig
		if s == syscall.SIGHUP {
			if _, err := reload(); err != nil {
				log.Error("reload failed", "err", err)
			}
			continue
		}
		break
	}

	log.Info("shutting down")
	close(stopWatch)
	mcCancel()
	licCancel()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if redirectSrv != nil {
		_ = redirectSrv.Shutdown(ctx)
	}
	_ = srv.Shutdown(ctx)
}

// siteHosts collects all configured site hostnames (for the self-signed cert).
func siteHosts(cfg *config.Config) []string {
	hosts := make([]string, 0, len(cfg.Sites))
	for _, s := range cfg.Sites {
		hosts = append(hosts, s.Host)
	}
	return hosts
}

// redirectHandler 301-redirects plain HTTP to HTTPS, preserving host and path.
func redirectHandler(httpsListen string) http.Handler {
	_, port, _ := net.SplitHostPort(httpsListen)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if i := strings.LastIndexByte(host, ':'); i != -1 && !strings.Contains(host, "]") {
			host = host[:i]
		}
		if port != "" && port != "443" {
			host = net.JoinHostPort(host, port)
		}
		http.Redirect(w, r, "https://"+host+r.URL.RequestURI(), http.StatusMovedPermanently)
	})
}

const agentVersion = "0.1.0"

// runLicenseAgent validates the key at startup and then heartbeats telemetry to
// the control plane, updating the guard's live license state. Fail-closed
// semantics: an explicit invalid/revoked response disables serving; a transient
// network error keeps the last known state (so a control-plane blip doesn't
// take production down once it has been licensed at least once).
func runLicenseAgent(ctx context.Context, cfg *config.Config, g *guard.Guard, bans *banlist.Store, mx *metrics.Metrics, log *slog.Logger) {
	client := license.NewClient(cfg.License.ServerURL, cfg.License.Key)
	host, _ := os.Hostname()
	fleetTTL := cfg.Ban.MaxDuration.Std() // local TTL for fleet-applied bans
	appliedBlocklist := 0
	protecting := cfg.License.Protecting
	if protecting == "" {
		if len(cfg.Sites) > 0 {
			protecting = cfg.Sites[0].Host
		} else {
			protecting = cfg.Upstream
		}
	}

	apply := func(licensed bool, reason string) {
		if cfg.License.FailOpen {
			return // fail-open never blocks locally
		}
		g.SetLicensed(licensed)
		if !licensed {
			log.Warn("license not active — proxy is failing closed", "reason", reason)
		}
	}

	// appliedPolicy is the policy version currently in effect on this agent.
	appliedPolicy := 0
	applyPolicy := func(doc *license.PolicyDoc, version int) {
		if doc == nil || version == appliedPolicy {
			return
		}
		merged := *cfg // shallow copy of the local base config
		doc.ApplyTo(&merged)
		merged.Normalize()
		if err := g.Reload(&merged); err != nil {
			log.Error("failed to apply pushed policy", "err", err, "version", version)
			return
		}
		appliedPolicy = version
		log.Info("applied pushed policy from control plane", "version", version)
	}

	// Startup validation.
	if resp, err := client.Validate(ctx); err != nil {
		log.Warn("control plane unreachable at startup", "err", err)
		// licensed stays false (fail-closed) until a check-in succeeds.
	} else if resp.Valid {
		apply(true, "")
		log.Info("license validated", "key_id", resp.KeyID, "name", resp.Name)
		applyPolicy(resp.Policy, resp.PolicyVersion)
	} else {
		apply(false, resp.Reason)
	}

	t := time.NewTicker(cfg.License.HeartbeatInterval.Std())
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			req := license.HeartbeatReq{
				Hostname:      host,
				Version:       agentVersion,
				Protecting:    protecting,
				PolicyVersion: appliedPolicy,
				Stats:         statsMap(mx),
			}
			if cfg.License.FleetBans {
				req.RecentBans = bans.DrainRecent() // share IPs we banned
				req.BlocklistVersion = appliedBlocklist
			}
			resp, err := client.Heartbeat(ctx, req)
			if err != nil {
				log.Warn("license heartbeat failed (keeping last state)", "err", err)
				continue
			}
			apply(resp.Licensed, resp.Reason)
			applyPolicy(resp.Policy, resp.PolicyVersion)

			// Apply the fleet blocklist when the control plane sent a new one
			// (non-nil = changed). Fleet bans don't escalate or re-report.
			if cfg.License.FleetBans && resp.Blocklist != nil {
				for _, ip := range resp.Blocklist {
					bans.BanFleet(ip, fleetTTL)
				}
				appliedBlocklist = resp.BlocklistVersion
				log.Info("applied fleet blocklist", "version", resp.BlocklistVersion, "ips", len(resp.Blocklist))
			}
		}
	}
}

func statsMap(mx *metrics.Metrics) map[string]int64 {
	return map[string]int64{
		"total_requests": mx.Total.Load(),
		"allowed":        mx.Allowed.Load(),
		"blocked_banned": mx.BlockedBanned.Load(),
		"bans_issued":    mx.BansIssued.Load(),
		"challenged":     mx.Challenged.Load(),
	}
}

// telemetryGate requires the admin token (X-AggerShield-Token header or ?token=)
// before serving a read-only telemetry endpoint. The query param lets you open
// the dashboard in a browser: https://host/aggershield/security?token=...
func telemetryGate(token string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		got := r.Header.Get("X-AggerShield-Token")
		if got == "" {
			got = r.URL.Query().Get("token")
		}
		if subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func newLogger(c config.Log) *slog.Logger {
	opts := &slog.HandlerOptions{Level: c.SlogLevel()}
	if c.Format == "json" {
		return slog.New(slog.NewJSONHandler(os.Stdout, opts))
	}
	return slog.New(slog.NewTextHandler(os.Stdout, opts))
}

// watchConfig polls the config file's modification time and reloads on change.
func watchConfig(path string, interval time.Duration, reload func() (*config.Config, error), log *slog.Logger, stop <-chan struct{}) {
	var lastMod time.Time
	if fi, err := os.Stat(path); err == nil {
		lastMod = fi.ModTime()
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			fi, err := os.Stat(path)
			if err != nil {
				continue
			}
			if fi.ModTime().After(lastMod) {
				lastMod = fi.ModTime()
				if _, err := reload(); err != nil {
					log.Error("auto-reload failed", "err", err)
				} else {
					log.Info("auto-reloaded config", "path", path)
				}
			}
		}
	}
}
