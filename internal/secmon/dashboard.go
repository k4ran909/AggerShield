package secmon

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// SamplesHandler serves the traffic time-series as JSON (chart data / API).
func (m *Monitor) SamplesHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, m.Samples())
	}
}

// EventsHandler serves the attack-event log as JSON (newest first).
func (m *Monitor) EventsHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, m.Events())
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// DashboardHandler serves the live "Network Security" HTML dashboard: current
// mitigation state, traffic charts (inline SVG), and the attack-event log.
func (m *Monitor) DashboardHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		samples := m.Samples()
		events := m.Events()
		state := m.State()

		// Chart the most recent ~120 points for readability.
		view := samples
		if len(view) > 120 {
			view = view[len(view)-120:]
		}
		reqs := make([]int64, len(view))
		blocked := make([]int64, len(view))
		for i, s := range view {
			reqs[i] = s.Reqs
			blocked[i] = s.Blocked
		}
		var curReqs, curBlocked int64
		if len(view) > 0 {
			curReqs = view[len(view)-1].Reqs
			curBlocked = view[len(view)-1].Blocked
		}

		badge := `<span class="pill ok">● NORMAL</span>`
		if state == "under_attack" {
			badge = `<span class="pill bad">● UNDER ATTACK — mitigating</span>`
		}

		var rows strings.Builder
		if len(events) == 0 {
			rows.WriteString(`<tr><td colspan="5" class="mut">No attack events recorded.</td></tr>`)
		}
		for _, e := range events {
			end, dur := "ongoing", time.Since(e.Start)
			if !e.Ongoing() {
				end = e.End.UTC().Format("15:04:05")
				dur = e.End.Sub(e.Start)
			}
			fmt.Fprintf(&rows,
				`<tr><td class="mono">%s</td><td class="mono">%s</td><td>%s</td><td class="mono">%d</td><td class="mono">%d</td></tr>`,
				e.Start.UTC().Format("2006-01-02 15:04:05"), end, dur.Round(time.Second),
				e.PeakReqs, e.TotalMitigated)
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, securityHTML, badge,
			curReqs, curBlocked, len(events),
			sparkline(reqs, 720, 90, "#4ea1ff"),
			sparkline(blocked, 720, 90, "#e74c3c"),
			rows.String(),
			time.Now().UTC().Format(time.RFC1123))
	}
}

// sparkline renders values as an inline SVG polyline (no JS).
func sparkline(vals []int64, w, h int, stroke string) string {
	if len(vals) == 0 {
		return fmt.Sprintf(`<svg width="%d" height="%d"></svg>`, w, h)
	}
	var max int64 = 1
	for _, v := range vals {
		if v > max {
			max = v
		}
	}
	denom := len(vals) - 1
	if denom < 1 {
		denom = 1
	}
	var pts strings.Builder
	for i, v := range vals {
		x := float64(i) / float64(denom) * float64(w)
		y := float64(h) - (float64(v)/float64(max))*float64(h-4) - 2
		fmt.Fprintf(&pts, "%.1f,%.1f ", x, y)
	}
	return fmt.Sprintf(
		`<svg width="100%%" height="%d" viewBox="0 0 %d %d" preserveAspectRatio="none">`+
			`<polyline fill="none" stroke="%s" stroke-width="1.5" points="%s"/></svg>`,
		h, w, h, stroke, strings.TrimSpace(pts.String()))
}

const securityHTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="refresh" content="5">
<title>AggerShield — Network Security</title>
<style>
:root{--bg:#0f1115;--card:#181b22;--line:#272b34;--fg:#e6e8ec;--mut:#9aa3b2;--ok:#2ecc71;--bad:#e74c3c}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 system-ui,sans-serif}
.wrap{max-width:820px;margin:0 auto;padding:24px}h1{font-size:20px;margin:0 0 4px}
.sub{color:var(--mut);margin-bottom:20px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:18px;margin-bottom:18px}
.pill{display:inline-block;padding:3px 12px;border-radius:999px;font-size:13px;font-weight:700}
.pill.ok{background:rgba(46,204,113,.15);color:var(--ok)}
.pill.bad{background:rgba(231,76,60,.18);color:var(--bad)}
.stats{display:flex;gap:28px;margin:8px 0 0}.stat .n{font-size:24px;font-weight:700}.stat .l{color:var(--mut);font-size:12px}
.lbl{color:var(--mut);font-size:12px;text-transform:uppercase;letter-spacing:.04em;margin-bottom:6px}
table{width:100%%;border-collapse:collapse}th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line)}
th{color:var(--mut);font-weight:600;font-size:12px;text-transform:uppercase}
.mut{color:var(--mut)}.mono{font-family:ui-monospace,monospace}
</style></head>
<body><div class="wrap">
<h1>🛡️ AggerShield — Network Security</h1>
<div class="sub">Live traffic, automatic attack detection, and the mitigation activity log.</div>

<div class="card">
  %s
  <div class="stats">
    <div class="stat"><div class="n">%d</div><div class="l">requests / interval</div></div>
    <div class="stat"><div class="n">%d</div><div class="l">blocked / interval</div></div>
    <div class="stat"><div class="n">%d</div><div class="l">attack events</div></div>
  </div>
</div>

<div class="card">
  <div class="lbl">Requests / interval</div>
  %s
</div>
<div class="card">
  <div class="lbl">Blocked / interval</div>
  %s
</div>

<div class="card">
  <strong>Attack activity log</strong>
  <table style="margin-top:10px">
    <thead><tr><th>Started (UTC)</th><th>Ended</th><th>Duration</th><th>Peak req/iv</th><th>Total mitigated</th></tr></thead>
    <tbody>%s</tbody>
  </table>
</div>
<div class="mut" style="font-size:12px">Auto-refreshes every 5s · %s</div>
</div></body></html>`
