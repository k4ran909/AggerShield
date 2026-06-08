// Package metrics holds lightweight atomic counters for live observability.
package metrics

import (
	"encoding/json"
	"net/http"
	"sync/atomic"
	"time"
)

// Metrics tracks request outcomes. All fields are updated atomically so the
// hot path stays lock-free.
type Metrics struct {
	startedAt time.Time

	Total         atomic.Int64
	Allowed       atomic.Int64
	BlockedBanned atomic.Int64
	RateLimitedIP atomic.Int64
	RateLimitedGl atomic.Int64
	ConnRejected  atomic.Int64
	BansIssued    atomic.Int64
	Challenged    atomic.Int64
	WouldBlock    atomic.Int64 // dry-run: decisions that would have blocked

	// Minecraft proxy.
	McConnTotal    atomic.Int64
	McConnRejected atomic.Int64
}

func New() *Metrics { return &Metrics{startedAt: time.Now()} }

// Snapshot is a JSON-serialisable view of the counters.
type Snapshot struct {
	UptimeSeconds      float64 `json:"uptime_seconds"`
	Total              int64   `json:"total_requests"`
	Allowed            int64   `json:"allowed"`
	BlockedBanned      int64   `json:"blocked_banned"`
	RateLimitedPerIP   int64   `json:"rate_limited_per_ip"`
	RateLimitedGlobal  int64   `json:"rate_limited_global"`
	ConnectionRejected int64   `json:"connection_rejected"`
	BansIssued         int64   `json:"bans_issued"`
	Challenged         int64   `json:"challenged"`
	WouldBlock         int64   `json:"would_block_dry_run"`
	McConnTotal        int64   `json:"mc_connections"`
	McConnRejected     int64   `json:"mc_rejected"`
	BannedIPsTracked   int     `json:"banned_ips_tracked"`
}

// Handler returns an http.HandlerFunc that serves the current snapshot as
// JSON. trackedFn supplies the live ban-table size.
func (m *Metrics) Handler(trackedFn func() int) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		s := Snapshot{
			UptimeSeconds:      time.Since(m.startedAt).Seconds(),
			Total:              m.Total.Load(),
			Allowed:            m.Allowed.Load(),
			BlockedBanned:      m.BlockedBanned.Load(),
			RateLimitedPerIP:   m.RateLimitedIP.Load(),
			RateLimitedGlobal:  m.RateLimitedGl.Load(),
			ConnectionRejected: m.ConnRejected.Load(),
			BansIssued:         m.BansIssued.Load(),
			Challenged:         m.Challenged.Load(),
			WouldBlock:         m.WouldBlock.Load(),
			McConnTotal:        m.McConnTotal.Load(),
			McConnRejected:     m.McConnRejected.Load(),
			BannedIPsTracked:   trackedFn(),
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(s)
	}
}
