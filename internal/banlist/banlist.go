// Package banlist implements an in-memory, TTL-based ban store with
// auto-unban and escalating durations for repeat offenders.
//
// Design notes (the "think like the attacker" parts):
//   - Every ban has an expiry; a background sweeper reaps expired entries,
//     so IPs are unbanned automatically without operator action.
//   - The table is size-capped. A flood of unique/spoofed source IPs must
//     never grow our memory without bound, or the ban table itself becomes
//     the denial-of-service. When full we evict the soonest-to-expire entry.
//   - Repeat offenders get exponentially longer bans (escalation), so an IP
//     that keeps coming back costs the attacker more each time.
package banlist

import (
	"math"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"aggershield/internal/netutil"
)

type entry struct {
	expires  time.Time
	offenses int
}

// Store is a concurrency-safe ban table.
type Store struct {
	mu     sync.Mutex
	banned map[string]*entry

	// allowNets is read lock-free (IsAllowed runs before IsBanned locks), so
	// it is swapped atomically to support hot-reload of the allowlist.
	allowNets atomic.Pointer[[]*net.IPNet]

	base       time.Duration
	max        time.Duration
	escalation float64
	maxEntries int

	// forget keeps offence history around past expiry so escalation works
	// for IPs that return, while still bounding memory.
	forget time.Duration

	stop chan struct{}
}

// New builds a Store and starts its auto-unban sweeper.
func New(base, max time.Duration, escalation float64, sweep time.Duration, maxEntries int, allowlist []string) *Store {
	s := &Store{
		banned:     make(map[string]*entry),
		base:       base,
		max:        max,
		escalation: escalation,
		maxEntries: maxEntries,
		forget:     max, // remember offences for one max-ban window
		stop:       make(chan struct{}),
	}
	s.SetAllowlist(allowlist)
	go s.sweepLoop(sweep)
	return s
}

// IsAllowed reports whether an IP is on the never-ban allowlist.
func (s *Store) IsAllowed(ip string) bool {
	if p := s.allowNets.Load(); p != nil {
		return netutil.Contains(*p, ip)
	}
	return false
}

// SetAllowlist replaces the never-ban allowlist (hot-reloadable).
func (s *Store) SetAllowlist(cidrs []string) {
	nets := netutil.ParseCIDRs(cidrs)
	s.allowNets.Store(&nets)
}

// SetParams updates the ban-duration tunables at runtime.
func (s *Store) SetParams(base, max time.Duration, escalation float64, maxEntries int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.base, s.max, s.escalation, s.maxEntries, s.forget = base, max, escalation, maxEntries, max
}

// Unban removes an IP from the ban table immediately. Reports whether it was
// present.
func (s *Store) Unban(ip string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.banned[ip]; ok {
		delete(s.banned, ip)
		return true
	}
	return false
}

// BanFor bans an IP for a fixed duration (used by the admin API). Allowlisted
// IPs are never banned.
func (s *Store) BanFor(ip string, d time.Duration) bool {
	if s.IsAllowed(ip) {
		return false
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.banned[ip]
	if !ok {
		if len(s.banned) >= s.maxEntries {
			s.evictLocked(now)
		}
		e = &entry{}
		s.banned[ip] = e
	}
	e.offenses++
	e.expires = now.Add(d)
	return true
}

// BanInfo is a snapshot of one active ban for the admin API.
type BanInfo struct {
	IP        string `json:"ip"`
	ExpiresIn string `json:"expires_in"`
	Offenses  int    `json:"offenses"`
}

// List returns all currently-active bans.
func (s *Store) List() []BanInfo {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]BanInfo, 0, len(s.banned))
	for ip, e := range s.banned {
		if now.Before(e.expires) {
			out = append(out, BanInfo{
				IP:        ip,
				ExpiresIn: e.expires.Sub(now).Round(time.Second).String(),
				Offenses:  e.offenses,
			})
		}
	}
	return out
}

// IsBanned reports whether an IP is currently banned.
func (s *Store) IsBanned(ip string) bool {
	if s.IsAllowed(ip) {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.banned[ip]
	if !ok {
		return false
	}
	return time.Now().Before(e.expires)
}

// Ban bans an IP, escalating the duration if it has offended before.
// Allowlisted IPs are never banned. Returns the applied ban duration.
func (s *Store) Ban(ip string) time.Duration {
	if s.IsAllowed(ip) {
		return 0
	}
	now := time.Now()

	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok := s.banned[ip]
	if !ok {
		if len(s.banned) >= s.maxEntries {
			s.evictLocked(now)
		}
		e = &entry{}
		s.banned[ip] = e
	}
	e.offenses++

	// duration = base * escalation^(offenses-1), capped at max.
	d := time.Duration(float64(s.base) * math.Pow(s.escalation, float64(e.offenses-1)))
	if d > s.max || d <= 0 {
		d = s.max
	}
	e.expires = now.Add(d)
	return d
}

// Count returns the number of tracked entries (banned + recently remembered).
func (s *Store) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.banned)
}

// Close stops the sweeper goroutine.
func (s *Store) Close() { close(s.stop) }

func (s *Store) sweepLoop(interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-t.C:
			s.sweep()
		}
	}
}

// sweep performs auto-unban: entries are dropped once their ban expired and
// the forget window has elapsed (so escalation history is kept for a while).
func (s *Store) sweep() {
	cutoff := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for ip, e := range s.banned {
		if cutoff.After(e.expires.Add(s.forget)) {
			delete(s.banned, ip)
		}
	}
}

// evictLocked frees space when the table is full by removing the entry whose
// ban expires soonest. Caller must hold s.mu.
func (s *Store) evictLocked(now time.Time) {
	var victim string
	var soonest time.Time
	first := true
	for ip, e := range s.banned {
		// Prefer already-expired entries.
		if now.After(e.expires) {
			delete(s.banned, ip)
			return
		}
		if first || e.expires.Before(soonest) {
			soonest, victim, first = e.expires, ip, false
		}
	}
	if victim != "" {
		delete(s.banned, victim)
	}
}
