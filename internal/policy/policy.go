// Package policy bundles every config-derived value the guard consults on the
// request hot path into a single immutable Snapshot. The guard holds the
// Snapshot behind an atomic pointer, so a hot-reload is just "build a new
// Snapshot and atomically swap it in" — in-flight requests keep using the old
// one and finish cleanly, with no locks on the hot path.
//
// Long-lived, stateful components (ban table, challenge manager, connection
// limiter) are NOT part of the Snapshot: their internal state must survive a
// reload, so they expose setters that the reloader calls instead.
package policy

import (
	"net"
	"strings"
	"time"

	"aggershield/internal/config"
	"aggershield/internal/netutil"
	"aggershield/internal/ratelimit"
	"aggershield/internal/rules"
)

const (
	defaultGCInterval = 30 * time.Second
	defaultIdle       = 5 * time.Minute
)

// Snapshot is an immutable view of the active policy.
type Snapshot struct {
	Trusted  []*net.IPNet
	DenyNets []*net.IPNet
	BadUAs   []string // lower-cased substrings

	DefaultPerIP *ratelimit.PerIP
	Global       *ratelimit.Global
	Rules        *rules.Set

	ChallengeEnabled    bool
	ChallengeAlways     bool
	ChallengeNonBrowser bool
	PressureThreshold   float64

	DryRun bool

	MaxBodyBytes int64
	BlockStatus  int
	BlockMessage string

	TarpitEnabled bool
	TarpitDelay   time.Duration
}

// Build constructs a Snapshot from config. It creates fresh rate limiters
// (per the configured limits); callers Close() the previous Snapshot after
// swapping this one in.
func Build(c *config.Config) (*Snapshot, error) {
	rs, err := rules.Compile(c.Rules, c.Ban.MaxEntries)
	if err != nil {
		return nil, err
	}

	badUAs := make([]string, 0, len(c.BadUserAgents))
	for _, ua := range c.BadUserAgents {
		badUAs = append(badUAs, strings.ToLower(ua))
	}

	return &Snapshot{
		Trusted:  netutil.ParseCIDRs(c.TrustedProxies),
		DenyNets: netutil.ParseCIDRs(c.Denylist),
		BadUAs:   badUAs,
		DefaultPerIP: ratelimit.NewPerIP(
			c.RateLimit.PerIPRPS, c.RateLimit.PerIPBurst,
			c.Ban.MaxEntries, defaultGCInterval, defaultIdle,
		),
		Global:              ratelimit.NewGlobal(c.RateLimit.GlobalRPS, c.RateLimit.GlobalBurst),
		Rules:               rs,
		ChallengeEnabled:    c.Challenge.Enabled,
		ChallengeAlways:     c.Challenge.Mode == "always",
		ChallengeNonBrowser: c.Challenge.ChallengeNonBrowser,
		PressureThreshold:   c.Challenge.PressureThreshold,
		DryRun:              c.DryRun,
		MaxBodyBytes:        c.Connection.MaxBodyBytes,
		BlockStatus:         c.Block.Status,
		BlockMessage:        c.Block.Message,
		TarpitEnabled:       c.Tarpit.Enabled,
		TarpitDelay:         c.Tarpit.Delay.Std(),
	}, nil
}

// Close releases the limiter goroutines owned by this Snapshot. Call it on the
// OLD snapshot after swapping in a new one.
func (s *Snapshot) Close() {
	if s == nil {
		return
	}
	if s.DefaultPerIP != nil {
		s.DefaultPerIP.Close()
	}
	s.Rules.Close()
}
