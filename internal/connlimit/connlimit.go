// Package connlimit caps the number of concurrent in-flight requests per IP.
//
// This is a cheap, effective defence against connection-exhaustion and
// slow-attack styles (Slowloris, RUDY) where each connection is individually
// low-volume but a single source opens very many of them at once.
package connlimit

import (
	"sync"
	"sync/atomic"
)

// Limiter tracks concurrent in-flight requests keyed by client IP.
type Limiter struct {
	mu     sync.Mutex
	active map[string]int
	max    atomic.Int64 // hot-reloadable cap (0 = unlimited)
}

func New(max int) *Limiter {
	l := &Limiter{active: make(map[string]int)}
	l.max.Store(int64(max))
	return l
}

// SetMax updates the concurrency cap at runtime.
func (l *Limiter) SetMax(max int) { l.max.Store(int64(max)) }

// Acquire reserves a slot for ip. It returns false if the IP is already at
// its concurrency cap; otherwise it returns a release func to call when done.
func (l *Limiter) Acquire(ip string) (release func(), ok bool) {
	max := int(l.max.Load())
	l.mu.Lock()
	defer l.mu.Unlock()
	if max > 0 && l.active[ip] >= max {
		return nil, false
	}
	l.active[ip]++
	return func() {
		l.mu.Lock()
		defer l.mu.Unlock()
		if l.active[ip] <= 1 {
			delete(l.active, ip)
		} else {
			l.active[ip]--
		}
	}, true
}
