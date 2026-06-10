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
	"encoding/json"
	"math"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"aggershield/internal/netutil"
)

// recentCap bounds the buffer of locally-issued bans awaiting report to the
// control plane (fleet sharing).
const recentCap = 1024

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

	// recent buffers IPs banned locally (by Ban/BanFor) since the last drain,
	// so the agent can report them to the control plane for fleet sharing.
	// Fleet-applied bans (BanFleet) are deliberately NOT recorded, to avoid an
	// echo loop between agents.
	recent []string

	// persistPath, if set, is where active bans are snapshotted so they
	// survive a restart.
	persistPath string

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
	s.recordRecentLocked(ip)
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
	s.recordRecentLocked(ip)
	return d
}

// recordRecentLocked appends a locally-banned IP to the report buffer. Caller
// must hold s.mu.
func (s *Store) recordRecentLocked(ip string) {
	if len(s.recent) >= recentCap {
		// Bound memory: drop the oldest half.
		s.recent = append(s.recent[:0:0], s.recent[recentCap/2:]...)
	}
	s.recent = append(s.recent, ip)
}

// DrainRecent returns and clears the IPs banned locally since the last call
// (deduped), for the agent to report to the control plane.
func (s *Store) DrainRecent() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.recent) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(s.recent))
	out := make([]string, 0, len(s.recent))
	for _, ip := range s.recent {
		if _, ok := seen[ip]; !ok {
			seen[ip] = struct{}{}
			out = append(out, ip)
		}
	}
	s.recent = nil
	return out
}

// BanFleet applies a fleet ban pushed from the control plane: a fixed-duration
// ban that does NOT escalate offences and is NOT recorded for re-reporting
// (avoiding an echo loop). Allowlisted IPs are still never banned.
func (s *Store) BanFleet(ip string, d time.Duration) {
	if s.IsAllowed(ip) {
		return
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
	if exp := now.Add(d); exp.After(e.expires) {
		e.expires = exp
	}
}

// Count returns the number of tracked entries (banned + recently remembered).
func (s *Store) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.banned)
}

// Close stops the sweeper goroutine.
func (s *Store) Close() { close(s.stop) }

// persistRecord is the on-disk form of a ban.
type persistRecord struct {
	Expires  time.Time `json:"expires"`
	Offenses int       `json:"offenses"`
}

// EnablePersistence loads any saved bans from path and starts snapshotting
// active bans there every interval (and once more on Close), so bans survive a
// restart.
func (s *Store) EnablePersistence(path string, interval time.Duration) error {
	s.persistPath = path
	if err := s.load(); err != nil {
		return err
	}
	go s.persistLoop(interval)
	return nil
}

func (s *Store) load() error {
	raw, err := os.ReadFile(s.persistPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var recs map[string]persistRecord
	if err := json.Unmarshal(raw, &recs); err != nil {
		return err
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for ip, r := range recs {
		if r.Expires.After(now) && len(s.banned) < s.maxEntries {
			s.banned[ip] = &entry{expires: r.Expires, offenses: r.Offenses}
		}
	}
	return nil
}

func (s *Store) snapshot() error {
	now := time.Now()
	s.mu.Lock()
	recs := make(map[string]persistRecord, len(s.banned))
	for ip, e := range s.banned {
		if e.expires.After(now) {
			recs[ip] = persistRecord{Expires: e.expires, Offenses: e.offenses}
		}
	}
	s.mu.Unlock()

	raw, err := json.MarshalIndent(recs, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.persistPath + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.persistPath)
}

func (s *Store) persistLoop(interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-s.stop:
			_ = s.snapshot() // final save on shutdown
			return
		case <-t.C:
			_ = s.snapshot()
		}
	}
}

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
