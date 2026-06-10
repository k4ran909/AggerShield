package license

import (
	"sort"
	"time"
)

// AddFleetBans records IPs reported by an agent into the shared fleet
// blocklist with the given TTL, capped at max entries. The version moves only
// when the set of IPs actually changes (a new IP appears), so merely
// refreshing an existing IP's expiry doesn't churn every agent.
func (s *Store) AddFleetBans(ips []string, ttl time.Duration, max int) error {
	if len(ips) == 0 {
		return nil
	}
	exp := time.Now().Add(ttl)
	s.mu.Lock()
	defer s.mu.Unlock()
	changed := false
	for _, ip := range ips {
		if _, exists := s.d.Fleet[ip]; !exists {
			changed = true
		}
		s.d.Fleet[ip] = exp
	}
	if max > 0 && len(s.d.Fleet) > max {
		s.evictFleetLocked(max)
		changed = true
	}
	if changed {
		s.d.FleetVersion++
	}
	return s.save()
}

// FleetBlocklist returns the active blocklist IPs and the current version. It
// also sweeps expired entries (bumping the version if any were removed).
func (s *Store) FleetBlocklist() ([]string, int) {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := false
	out := make([]string, 0, len(s.d.Fleet))
	for ip, exp := range s.d.Fleet {
		if exp.After(now) {
			out = append(out, ip)
		} else {
			delete(s.d.Fleet, ip)
			removed = true
		}
	}
	if removed {
		s.d.FleetVersion++
		_ = s.save()
	}
	sort.Strings(out)
	return out, s.d.FleetVersion
}

// evictFleetLocked trims the blocklist to max by removing the soonest-to-expire
// entries. Caller holds s.mu.
func (s *Store) evictFleetLocked(max int) {
	type kv struct {
		ip  string
		exp time.Time
	}
	all := make([]kv, 0, len(s.d.Fleet))
	for ip, exp := range s.d.Fleet {
		all = append(all, kv{ip, exp})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].exp.Before(all[j].exp) })
	for i := 0; i < len(all)-max; i++ {
		delete(s.d.Fleet, all[i].ip)
	}
}
