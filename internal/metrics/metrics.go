// Package metrics holds lightweight atomic counters for live observability.
package metrics

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
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

// Prometheus returns an http.HandlerFunc serving the counters in Prometheus /
// OpenMetrics text exposition format, so AggerShield plugs straight into
// Prometheus + Grafana + Alertmanager. Rendered by hand (no client library) to
// keep the dependency footprint minimal. trackedFn supplies the live ban count.
func (m *Metrics) Prometheus(trackedFn func() int) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		var b strings.Builder
		counter := func(name, help string, v int64) {
			fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s counter\n%s %d\n", name, help, name, name, v)
		}
		gauge := func(name, help string, v float64) {
			fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s gauge\n%s %g\n", name, help, name, name, v)
		}
		counter("aggershield_requests_total", "Total requests seen", m.Total.Load())
		counter("aggershield_allowed_total", "Requests passed to the upstream", m.Allowed.Load())
		counter("aggershield_blocked_banned_total", "Requests blocked because the IP was banned", m.BlockedBanned.Load())
		counter("aggershield_rate_limited_per_ip_total", "Requests over the per-IP limit", m.RateLimitedIP.Load())
		counter("aggershield_rate_limited_global_total", "Requests shed by the global limiter", m.RateLimitedGl.Load())
		counter("aggershield_connection_rejected_total", "Requests rejected by the per-IP concurrency cap", m.ConnRejected.Load())
		counter("aggershield_bans_issued_total", "Bans issued", m.BansIssued.Load())
		counter("aggershield_challenged_total", "Proof-of-work challenges served", m.Challenged.Load())
		counter("aggershield_would_block_total", "Dry-run decisions that would have blocked", m.WouldBlock.Load())
		counter("aggershield_mc_connections_total", "Minecraft connections seen", m.McConnTotal.Load())
		counter("aggershield_mc_rejected_total", "Minecraft connections rejected", m.McConnRejected.Load())
		gauge("aggershield_banned_ips", "Currently tracked banned IPs", float64(trackedFn()))
		gauge("aggershield_uptime_seconds", "Process uptime in seconds", time.Since(m.startedAt).Seconds())

		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		_, _ = io.WriteString(w, b.String())
	}
}
