// Package secmon is AggerShield's "VAC-style" security monitor: an always-on
// sampler that records a per-interval traffic time-series, automatically opens
// and closes attack events (the mitigation lifecycle), and exposes the current
// mitigation state. It's the software half of an OVH-style "Network Security
// Dashboard" — activity logs + dynamic traffic charts + statistics — minus the
// physical Tbit/s scrubbing capacity, which only a network edge can provide.
package secmon

import (
	"sync"
	"time"
)

// Counters is a cumulative snapshot of the metrics the monitor samples.
type Counters struct {
	Total      int64 // all requests seen
	Allowed    int64
	Blocked    int64 // banned + rate-limited + conn-capped + fingerprint + bad-UA
	Challenged int64
	Bans       int64
}

// Sample is the per-interval delta (the points behind the traffic charts).
type Sample struct {
	T          time.Time `json:"t"`
	Reqs       int64     `json:"reqs"`
	Allowed    int64     `json:"allowed"`
	Blocked    int64     `json:"blocked"`
	Challenged int64     `json:"challenged"`
	Bans       int64     `json:"bans"`
}

// Event is one detected attack/mitigation episode.
type Event struct {
	Start        time.Time `json:"start"`
	End          time.Time `json:"end,omitempty"` // zero while ongoing
	PeakReqs     int64     `json:"peak_reqs"`     // peak requests/interval
	PeakBlocked  int64     `json:"peak_blocked"`  // peak blocked/interval
	TotalBlocked int64     `json:"total_blocked"`
	Reason       string    `json:"reason"`
}

// Ongoing reports whether the event has not yet ended.
func (e Event) Ongoing() bool { return e.End.IsZero() }

// Monitor samples counters on a fixed interval and tracks attack episodes.
type Monitor struct {
	mu       sync.Mutex
	ring     []Sample
	capN     int
	events   []Event
	eventCap int

	inAttack bool
	cur      Event
	calm     int

	interval      time.Duration
	attackBlocked int64 // blocked/interval that opens an event
	exitTicks     int   // calm intervals before closing an event

	snapshot func() Counters
	prev     Counters
	started  bool
	stop     chan struct{}
}

// New builds a Monitor. retain bounds the time-series ring; attackBlocked is
// the blocked-per-interval that opens an attack event; exitTicks is how many
// quiet intervals close it.
func New(interval time.Duration, retain int, attackBlocked int64, exitTicks int, snapshot func() Counters) *Monitor {
	if retain <= 0 {
		retain = 3600
	}
	if attackBlocked <= 0 {
		attackBlocked = 20
	}
	if exitTicks <= 0 {
		exitTicks = 5
	}
	return &Monitor{
		ring:          make([]Sample, 0, retain),
		capN:          retain,
		eventCap:      500,
		interval:      interval,
		attackBlocked: attackBlocked,
		exitTicks:     exitTicks,
		snapshot:      snapshot,
		stop:          make(chan struct{}),
	}
}

// Run samples every interval until Close. Call in a goroutine.
func (m *Monitor) Run() {
	t := time.NewTicker(m.interval)
	defer t.Stop()
	for {
		select {
		case <-m.stop:
			return
		case <-t.C:
			m.tick(time.Now())
		}
	}
}

// tick computes the per-interval delta, appends it, and runs attack detection.
// Tests in this package call it directly for deterministic timing.
func (m *Monitor) tick(now time.Time) {
	c := m.snapshot()
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.started {
		m.prev = c
		m.started = true
		return // first tick seeds the baseline; no delta yet
	}
	s := Sample{
		T:          now,
		Reqs:       nonNeg(c.Total - m.prev.Total),
		Allowed:    nonNeg(c.Allowed - m.prev.Allowed),
		Blocked:    nonNeg(c.Blocked - m.prev.Blocked),
		Challenged: nonNeg(c.Challenged - m.prev.Challenged),
		Bans:       nonNeg(c.Bans - m.prev.Bans),
	}
	m.prev = c

	if len(m.ring) >= m.capN {
		m.ring = append(m.ring[:0], m.ring[1:]...) // drop oldest
	}
	m.ring = append(m.ring, s)

	m.detect(s, now)
}

// detect opens/closes attack events based on the blocked rate.
func (m *Monitor) detect(s Sample, now time.Time) {
	if !m.inAttack {
		if s.Blocked >= m.attackBlocked {
			m.inAttack = true
			m.calm = 0
			m.cur = Event{Start: now, Reason: "elevated block rate", PeakReqs: s.Reqs, PeakBlocked: s.Blocked, TotalBlocked: s.Blocked}
		}
		return
	}
	// in attack: track peaks/totals
	if s.Reqs > m.cur.PeakReqs {
		m.cur.PeakReqs = s.Reqs
	}
	if s.Blocked > m.cur.PeakBlocked {
		m.cur.PeakBlocked = s.Blocked
	}
	m.cur.TotalBlocked += s.Blocked

	if s.Blocked < m.attackBlocked {
		m.calm++
		if m.calm >= m.exitTicks {
			m.cur.End = now
			m.appendEventLocked(m.cur)
			m.inAttack = false
			m.cur = Event{}
		}
	} else {
		m.calm = 0
	}
}

func (m *Monitor) appendEventLocked(e Event) {
	if len(m.events) >= m.eventCap {
		m.events = append(m.events[:0], m.events[1:]...)
	}
	m.events = append(m.events, e)
}

// Samples returns a copy of the time-series (oldest first).
func (m *Monitor) Samples() []Sample {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Sample, len(m.ring))
	copy(out, m.ring)
	return out
}

// Events returns attack events newest-first; an ongoing event is included.
func (m *Monitor) Events() []Event {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Event
	if m.inAttack {
		out = append(out, m.cur)
	}
	for i := len(m.events) - 1; i >= 0; i-- {
		out = append(out, m.events[i])
	}
	return out
}

// State is "under_attack" while an event is open, else "normal".
func (m *Monitor) State() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.inAttack {
		return "under_attack"
	}
	return "normal"
}

// Close stops the sampler.
func (m *Monitor) Close() { close(m.stop) }

func nonNeg(v int64) int64 {
	if v < 0 {
		return 0
	}
	return v
}
