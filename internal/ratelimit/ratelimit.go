// Package ratelimit provides token-bucket rate limiters.
//
// Two layers cooperate:
//
//   - PerIP limits a single source. Good against one noisy host.
//   - Global limits aggregate traffic. This is what blunts a distributed
//     botnet that deliberately keeps every individual IP under the per-IP
//     threshold — the textbook bypass of naive per-IP limiting.
//
// Per-IP buckets are garbage-collected when idle so a flood of unique source
// IPs cannot grow memory without bound.
package ratelimit

import (
	"sync"
	"time"
)

type bucket struct {
	tokens float64
	last   time.Time
}

// PerIP is a keyed token-bucket limiter (one bucket per client IP).
type PerIP struct {
	mu        sync.Mutex
	buckets   map[string]*bucket
	rps       float64
	burst     float64
	maxKeys   int
	stop      chan struct{}
	closeOnce sync.Once
}

// NewPerIP creates a per-IP limiter and starts its idle-bucket GC.
func NewPerIP(rps, burst float64, maxKeys int, gcInterval, idle time.Duration) *PerIP {
	p := &PerIP{
		buckets: make(map[string]*bucket),
		rps:     rps,
		burst:   burst,
		maxKeys: maxKeys,
		stop:    make(chan struct{}),
	}
	go p.gcLoop(gcInterval, idle)
	return p
}

// Allow consumes one token for key. It returns false when the bucket is empty
// (i.e. the client is over its rate).
func (p *PerIP) Allow(key string) bool {
	now := time.Now()
	p.mu.Lock()
	defer p.mu.Unlock()

	b, ok := p.buckets[key]
	if !ok {
		if p.maxKeys > 0 && len(p.buckets) >= p.maxKeys {
			p.evictLocked(now)
		}
		b = &bucket{tokens: p.burst, last: now}
		p.buckets[key] = b
	}
	refill(b, now, p.rps, p.burst)
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

func (p *PerIP) gcLoop(interval, idle time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-p.stop:
			return
		case <-t.C:
			p.gc(idle)
		}
	}
}

// gc removes buckets that are full (no recent activity) and idle, reclaiming
// memory from one-off clients.
func (p *PerIP) gc(idle time.Duration) {
	cutoff := time.Now().Add(-idle)
	p.mu.Lock()
	defer p.mu.Unlock()
	for k, b := range p.buckets {
		if b.last.Before(cutoff) && b.tokens >= p.burst {
			delete(p.buckets, k)
		}
	}
}

func (p *PerIP) evictLocked(now time.Time) {
	// Drop the least-recently-used bucket to make room.
	var victim string
	var oldest time.Time
	first := true
	for k, b := range p.buckets {
		if first || b.last.Before(oldest) {
			oldest, victim, first = b.last, k, false
		}
	}
	if victim != "" {
		delete(p.buckets, victim)
	}
}

// Close stops the GC goroutine. Safe to call multiple times.
func (p *PerIP) Close() { p.closeOnce.Do(func() { close(p.stop) }) }

// Global is a single token bucket covering all traffic.
type Global struct {
	mu  sync.Mutex
	b   bucket
	rps float64
	cap float64
}

// NewGlobal creates an aggregate limiter.
func NewGlobal(rps, burst float64) *Global {
	return &Global{b: bucket{tokens: burst, last: time.Now()}, rps: rps, cap: burst}
}

// Allow consumes one token from the global bucket.
func (g *Global) Allow() bool {
	now := time.Now()
	g.mu.Lock()
	defer g.mu.Unlock()
	refill(&g.b, now, g.rps, g.cap)
	if g.b.tokens >= 1 {
		g.b.tokens--
		return true
	}
	return false
}

// Remaining returns the fraction of global capacity still available (0..1).
// A low value means the aggregate ceiling is under pressure — used to decide
// when "adaptive" challenge mode should kick in.
func (g *Global) Remaining() float64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	refill(&g.b, time.Now(), g.rps, g.cap)
	if g.cap <= 0 {
		return 1
	}
	return g.b.tokens / g.cap
}

// refill tops up a bucket based on elapsed time, capped at burst.
func refill(b *bucket, now time.Time, rps, burst float64) {
	elapsed := now.Sub(b.last).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * rps
		if b.tokens > burst {
			b.tokens = burst
		}
		b.last = now
	}
}
