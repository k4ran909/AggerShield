// Package config loads and validates AggerShield's runtime configuration.
//
// Config is intentionally plain JSON (zero external dependencies) so the
// project builds offline on any OS. Durations are written as human strings
// ("60s", "1h") and parsed into time.Duration.
package config

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"time"
)

// Config is the top-level runtime configuration.
type Config struct {
	// Listen is the plain-HTTP address AggerShield serves on, e.g. ":8080".
	// When tls.enabled is set, HTTPS uses tls.https_listen instead.
	Listen string `json:"listen"`
	// Upstream is the default/fallback backend, e.g. "http://127.0.0.1:3000"
	// or "https://myapp.vercel.app". Used for any Host not matched by Sites.
	Upstream string `json:"upstream"`
	// Sites enables host-based routing: each incoming Host can map to its own
	// origin. This lets one AggerShield protect several hosted sites at once.
	Sites []Site `json:"sites"`
	// TrustedProxies are CIDRs/IPs we trust to set X-Forwarded-For.
	// Empty = trust nobody, always use the raw TCP peer address.
	// (XFF is attacker-spoofable; never trust it blindly.)
	TrustedProxies []string `json:"trusted_proxies"`
	// Allowlist are IPs/CIDRs that are never rate-limited or banned
	// (admins, payment webhooks, health checks). Critical for ecommerce.
	Allowlist []string `json:"allowlist"`
	// Denylist are IPs/CIDRs that are always blocked outright.
	Denylist []string `json:"denylist"`
	// BadUserAgents are case-insensitive substrings; any request whose
	// User-Agent contains one is blocked (cheap bad-bot filter).
	BadUserAgents []string `json:"bad_user_agents"`

	// WatchInterval, if > 0, polls the config file and hot-reloads on change.
	WatchInterval Duration `json:"watch_interval"`

	// DryRun puts AggerShield in monitor-only mode: every block/limit/ban/
	// challenge decision is logged and counted but NOT enforced, so traffic
	// flows untouched. Use it to validate your config against real traffic
	// before turning enforcement on — the safest way to avoid hurting users.
	DryRun bool `json:"dry_run"`

	TLS       TLS       `json:"tls"`
	Minecraft Minecraft `json:"minecraft"`
	License   License   `json:"license"`

	RateLimit  RateLimit  `json:"rate_limit"`
	Ban        Ban        `json:"ban"`
	Connection Connection `json:"connection"`
	Challenge  Challenge  `json:"challenge"`
	Block      Block      `json:"block"`
	Admin      Admin      `json:"admin"`
	Log        Log        `json:"log"`
	// Rules are per-route overrides, evaluated top-to-bottom; the first match
	// wins. They let you protect specific endpoints (e.g. /login, /checkout)
	// far more strictly than the global defaults.
	Rules []Rule `json:"rules"`
}

// Site maps an incoming Host header to a specific origin. This is how one
// AggerShield instance protects multiple hosted sites.
type Site struct {
	// Host is the public hostname to match, e.g. "shop.example.com".
	Host string `json:"host"`
	// Upstream is the origin to forward to, e.g. "https://shop.vercel.app"
	// or "http://127.0.0.1:4000".
	Upstream string `json:"upstream"`
	// PreserveHost controls the Host header sent to the origin:
	//   true  -> keep the visitor's Host (typical for self-hosted/Dokploy,
	//            where the app is configured for its real domain).
	//   false -> rewrite to the upstream's host (REQUIRED for platforms like
	//            Vercel/Netlify that route by Host and only know their own
	//            *.vercel.app / *.netlify.app name).
	PreserveHost bool `json:"preserve_host"`
}

// TLS configures HTTPS termination. AggerShield can terminate TLS itself
// (so visitors connect over HTTPS) and forward to the origin.
type TLS struct {
	Enabled      bool   `json:"enabled"`
	HTTPSListen  string `json:"https_listen"`  // default ":443"
	HTTPListen   string `json:"http_listen"`   // default ":80" (for redirect)
	RedirectHTTP bool   `json:"redirect_http"` // 301 plain HTTP -> HTTPS
	// CertFile/KeyFile: bring your own PEM cert + key (Let's Encrypt, an OVH/
	// Cloudflare origin cert, etc.). Required unless SelfSigned is set.
	CertFile string `json:"cert_file"`
	KeyFile  string `json:"key_file"`
	// SelfSigned generates an in-memory self-signed cert at startup. For local
	// testing only (browsers will warn); use real certs in production.
	SelfSigned bool `json:"self_signed"`
	// AutoCert enables automatic HTTPS via ACME (Let's Encrypt): certificates
	// are obtained and renewed automatically. Takes precedence over
	// cert_file/self_signed. Requires the box to be reachable from the
	// internet on ports 80 (ACME HTTP-01 challenge) and 443.
	AutoCert AutoCert `json:"auto_cert"`
}

// License turns the proxy into a licensed agent that checks in with a central
// AggerShield control plane. When enabled and the key is invalid/revoked the
// agent fails closed (stops serving) — unless FailOpen is set.
type License struct {
	Enabled   bool   `json:"enabled"`
	ServerURL string `json:"server_url"` // control plane base URL
	Key       string `json:"key"`        // this agent's license key (agsk_...)
	// Protecting is a human label for the dashboard (what this agent guards).
	// Defaults to the first site host or the upstream.
	Protecting string `json:"protecting"`
	// HeartbeatInterval is how often the agent reports status. Default 30s.
	HeartbeatInterval Duration `json:"heartbeat_interval"`
	// FailOpen keeps serving (unprotected-licensing) if the key can't be
	// confirmed. Default false = fail closed (revoked key => stop serving).
	FailOpen bool `json:"fail_open"`
	// FleetBans opts into shared threat intel: this agent reports IPs it bans
	// to the control plane and applies the fleet blocklist it gets back, so an
	// IP banned on any agent is blocked across the fleet.
	FleetBans bool `json:"fleet_bans"`
}

// Minecraft enables a protocol-aware TCP proxy in front of a Minecraft
// server. It parses the handshake to drop malformed connections, throttles
// new connections and per-IP concurrency, and shares the ban list with the
// HTTP guard. It defends server-list-ping floods and bot-join floods that
// generic TCP proxies miss.
type Minecraft struct {
	Enabled  bool   `json:"enabled"`
	Listen   string `json:"listen"`   // default ":25565"
	Upstream string `json:"upstream"` // real MC server, e.g. "127.0.0.1:25566"
	// MaxConnsPerIP caps concurrent connections from one IP.
	MaxConnsPerIP int `json:"max_conns_per_ip"`
	// NewConnsPerSec / NewConnsBurst rate-limit how fast one IP may open new
	// connections (the main lever against ping/join floods).
	NewConnsPerSec float64 `json:"new_conns_per_sec"`
	NewConnsBurst  float64 `json:"new_conns_burst"`
	// HandshakeTimeout drops clients that don't send a valid handshake in time
	// (anti-slowloris on the MC handshake).
	HandshakeTimeout Duration `json:"handshake_timeout"`
	// BanOnAbuse bans IPs that exceed the new-connection rate or send a
	// malformed handshake (using the shared ban list + auto-unban).
	BanOnAbuse bool `json:"ban_on_abuse"`
}

// AutoCert configures ACME / Let's Encrypt automatic certificates.
type AutoCert struct {
	Enabled bool `json:"enabled"`
	// Domains is the allowlist of hostnames to issue certs for. Site hosts are
	// added automatically; this is for any extra names.
	Domains []string `json:"domains"`
	// Email is the ACME account contact (recommended for expiry notices).
	Email string `json:"email"`
	// CacheDir stores issued certs+keys so restarts don't re-request them
	// (avoids Let's Encrypt rate limits). Default "./acme-cache".
	CacheDir string `json:"cache_dir"`
}

// Rule is a per-route override. A request matches when its path satisfies
// PathPrefix/PathRegex (if set) and its method is in Methods (if set).
type Rule struct {
	Name       string   `json:"name"`
	PathPrefix string   `json:"path_prefix"`
	PathRegex  string   `json:"path_regex"`
	Methods    []string `json:"methods"`
	// Action: "" (apply default protections), "allow" (skip all checks),
	// "block" (always block), or "challenge" (force a PoW challenge).
	Action string `json:"action"`
	// Optional per-IP rate override for this route (0 = inherit global default).
	PerIPRPS   float64 `json:"per_ip_rps"`
	PerIPBurst float64 `json:"per_ip_burst"`
}

// Block customises the response sent to blocked requests.
type Block struct {
	Status  int    `json:"status"`
	Message string `json:"message"`
}

// Admin configures the runtime control API (live ban/unban, reload, inspect).
type Admin struct {
	Enabled bool `json:"enabled"`
	// Token must be sent as the X-AggerShield-Token header. Required when
	// Enabled; mutating endpoints are refused if it is empty.
	Token string `json:"token"`
}

// Log configures structured logging.
type Log struct {
	Level  string `json:"level"`  // debug | info | warn | error
	Format string `json:"format"` // text | json
}

// Challenge configures the proof-of-work browser challenge — the defence
// against distributed botnets whose individual IPs stay under the per-IP
// limit. A real browser solves a one-time PoW (invisible, ~1s) and receives
// a signed clearance cookie; a flood client that doesn't run JS never passes.
type Challenge struct {
	Enabled bool `json:"enabled"`
	// Mode: "always" challenges every uncleared client (under-attack mode);
	// "adaptive" only challenges when the global limiter is under pressure.
	Mode string `json:"mode"`
	// DifficultyBits is the number of leading zero bits the PoW hash must
	// have. Each extra bit doubles the work. 12–16 is a good browser range.
	DifficultyBits int `json:"difficulty_bits"`
	// ClearanceTTL is how long a solved clearance cookie remains valid.
	ClearanceTTL Duration `json:"clearance_ttl"`
	// PressureThreshold (0..1): in "adaptive" mode, challenge clients once the
	// global limiter has less than this fraction of capacity remaining.
	PressureThreshold float64 `json:"pressure_threshold"`
	// ChallengeNonBrowser, when false (the default), only challenges requests
	// that accept text/html (i.e. browser navigations). This keeps APIs,
	// mobile apps, webhooks, and asset/XHR requests free of PoW challenges.
	// Set true to challenge every uncleared request regardless of type.
	ChallengeNonBrowser bool `json:"challenge_non_browser"`
	// Secret signs challenge tokens. Leave empty to generate a random secret
	// at startup (clearances then reset on restart). Changing it needs a
	// restart (not applied on hot-reload), as it invalidates live clearances.
	Secret string `json:"secret"`
}

// RateLimit holds per-IP and global token-bucket parameters.
//
// Per-IP limits stop a single noisy source. Global limits are what actually
// blunt a distributed botnet that keeps every individual IP under the per-IP
// threshold — the classic way naive per-IP limiting is bypassed.
type RateLimit struct {
	PerIPRPS    float64 `json:"per_ip_rps"`
	PerIPBurst  float64 `json:"per_ip_burst"`
	GlobalRPS   float64 `json:"global_rps"`
	GlobalBurst float64 `json:"global_burst"`
}

// Ban controls the offender ban store and the auto-unban behaviour.
type Ban struct {
	// BaseDuration is the first-offence ban length.
	BaseDuration Duration `json:"base_duration"`
	// MaxDuration caps escalated bans for repeat offenders.
	MaxDuration Duration `json:"max_duration"`
	// EscalationFactor multiplies the ban length per repeat offence
	// (e.g. 2.0 => 60s, 120s, 240s ...). Repeat attackers cost more.
	EscalationFactor float64 `json:"escalation_factor"`
	// SweepInterval is how often expired bans are reaped (auto-unban).
	SweepInterval Duration `json:"sweep_interval"`
	// MaxEntries caps tracked IPs so the ban table can't itself be a
	// memory-exhaustion DoS when flooded with unique/spoofed sources.
	MaxEntries int `json:"max_entries"`
	// PersistPath, if set, snapshots active bans to this file so they survive
	// a restart (loaded on startup, saved periodically + on shutdown).
	PersistPath string `json:"persist_path"`
}

// Connection holds slow-attack and connection-exhaustion protections.
type Connection struct {
	MaxPerIP          int      `json:"max_per_ip"`
	ReadHeaderTimeout Duration `json:"read_header_timeout"`
	ReadTimeout       Duration `json:"read_timeout"`
	WriteTimeout      Duration `json:"write_timeout"`
	IdleTimeout       Duration `json:"idle_timeout"`
	MaxHeaderBytes    int      `json:"max_header_bytes"`
	MaxBodyBytes      int64    `json:"max_body_bytes"`
}

// Duration is a time.Duration that (de)serialises from a JSON string.
type Duration time.Duration

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	*d = Duration(parsed)
	return nil
}

func (d Duration) Std() time.Duration { return time.Duration(d) }

// Load reads, parses, and validates a config file, applying defaults.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	c.applyDefaults()
	if err := c.validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// Normalize fills in default values for any unset fields. Use it after merging
// a partially-specified policy so zero values get sane defaults.
func (c *Config) Normalize() { c.applyDefaults() }

func (c *Config) applyDefaults() {
	if c.Listen == "" {
		c.Listen = ":8080"
	}
	if c.RateLimit.PerIPRPS == 0 {
		c.RateLimit.PerIPRPS = 20
	}
	if c.RateLimit.PerIPBurst == 0 {
		c.RateLimit.PerIPBurst = c.RateLimit.PerIPRPS * 2
	}
	if c.RateLimit.GlobalRPS == 0 {
		c.RateLimit.GlobalRPS = 5000
	}
	if c.RateLimit.GlobalBurst == 0 {
		c.RateLimit.GlobalBurst = c.RateLimit.GlobalRPS * 2
	}
	if c.Ban.BaseDuration == 0 {
		c.Ban.BaseDuration = Duration(60 * time.Second)
	}
	if c.Ban.MaxDuration == 0 {
		c.Ban.MaxDuration = Duration(time.Hour)
	}
	if c.Ban.EscalationFactor == 0 {
		c.Ban.EscalationFactor = 2.0
	}
	if c.Ban.SweepInterval == 0 {
		c.Ban.SweepInterval = Duration(10 * time.Second)
	}
	if c.Ban.MaxEntries == 0 {
		c.Ban.MaxEntries = 1_000_000
	}
	if c.Connection.MaxPerIP == 0 {
		c.Connection.MaxPerIP = 50
	}
	if c.Connection.ReadHeaderTimeout == 0 {
		c.Connection.ReadHeaderTimeout = Duration(5 * time.Second)
	}
	if c.Connection.ReadTimeout == 0 {
		c.Connection.ReadTimeout = Duration(15 * time.Second)
	}
	if c.Connection.WriteTimeout == 0 {
		c.Connection.WriteTimeout = Duration(20 * time.Second)
	}
	if c.Connection.IdleTimeout == 0 {
		c.Connection.IdleTimeout = Duration(60 * time.Second)
	}
	if c.Connection.MaxHeaderBytes == 0 {
		c.Connection.MaxHeaderBytes = 16 << 10 // 16 KiB
	}
	if c.Connection.MaxBodyBytes == 0 {
		c.Connection.MaxBodyBytes = 1 << 20 // 1 MiB
	}
	if c.Challenge.Mode == "" {
		c.Challenge.Mode = "adaptive"
	}
	if c.Challenge.DifficultyBits == 0 {
		c.Challenge.DifficultyBits = 14
	}
	if c.Challenge.ClearanceTTL == 0 {
		c.Challenge.ClearanceTTL = Duration(30 * time.Minute)
	}
	if c.Challenge.PressureThreshold == 0 {
		c.Challenge.PressureThreshold = 0.25
	}
	if c.Block.Status == 0 {
		c.Block.Status = 403
	}
	if c.Block.Message == "" {
		c.Block.Message = "Forbidden"
	}
	if c.Log.Level == "" {
		c.Log.Level = "info"
	}
	if c.Log.Format == "" {
		c.Log.Format = "text"
	}
	if c.TLS.HTTPSListen == "" {
		c.TLS.HTTPSListen = ":443"
	}
	if c.TLS.HTTPListen == "" {
		c.TLS.HTTPListen = ":80"
	}
	if c.TLS.AutoCert.CacheDir == "" {
		c.TLS.AutoCert.CacheDir = "./acme-cache"
	}
	if c.Minecraft.Listen == "" {
		c.Minecraft.Listen = ":25565"
	}
	if c.Minecraft.MaxConnsPerIP == 0 {
		c.Minecraft.MaxConnsPerIP = 8
	}
	if c.Minecraft.NewConnsPerSec == 0 {
		c.Minecraft.NewConnsPerSec = 5
	}
	if c.Minecraft.NewConnsBurst == 0 {
		c.Minecraft.NewConnsBurst = 10
	}
	if c.Minecraft.HandshakeTimeout == 0 {
		c.Minecraft.HandshakeTimeout = Duration(5 * time.Second)
	}
	if c.License.HeartbeatInterval == 0 {
		c.License.HeartbeatInterval = Duration(30 * time.Second)
	}
}

func (c *Config) validate() error {
	if c.Upstream == "" && len(c.Sites) == 0 {
		return fmt.Errorf("config: set 'upstream' and/or at least one 'sites' entry")
	}
	for i, s := range c.Sites {
		if s.Host == "" || s.Upstream == "" {
			return fmt.Errorf("config: site %d needs both 'host' and 'upstream'", i)
		}
	}
	if c.TLS.Enabled && !c.TLS.AutoCert.Enabled && !c.TLS.SelfSigned && (c.TLS.CertFile == "" || c.TLS.KeyFile == "") {
		return fmt.Errorf("config: tls.enabled requires auto_cert, cert_file+key_file, or self_signed")
	}
	if c.TLS.AutoCert.Enabled && len(c.TLS.AutoCert.Domains) == 0 && len(c.Sites) == 0 {
		return fmt.Errorf("config: auto_cert needs at least one domain (auto_cert.domains or sites[].host)")
	}
	if c.Minecraft.Enabled && c.Minecraft.Upstream == "" {
		return fmt.Errorf("config: minecraft.enabled requires minecraft.upstream")
	}
	if c.License.Enabled && (c.License.ServerURL == "" || c.License.Key == "") {
		return fmt.Errorf("config: license.enabled requires server_url and key")
	}
	for i, r := range c.Rules {
		switch r.Action {
		case "", "allow", "block", "challenge":
		default:
			return fmt.Errorf("config: rule %d (%q) has invalid action %q (want allow|block|challenge or empty)", i, r.Name, r.Action)
		}
	}
	if c.Admin.Enabled && c.Admin.Token == "" {
		return fmt.Errorf("config: admin.enabled requires a non-empty admin.token")
	}
	switch c.Log.Level {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("config: invalid log.level %q", c.Log.Level)
	}
	return nil
}

// SlogLevel maps the configured level to a slog.Level.
func (l Log) SlogLevel() slog.Level {
	switch l.Level {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
