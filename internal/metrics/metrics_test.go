package metrics

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPrometheusOutput(t *testing.T) {
	m := New()
	m.Total.Add(7)
	m.BansIssued.Add(2)

	rec := httptest.NewRecorder()
	m.Prometheus(func() int { return 3 }).ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))

	body := rec.Body.String()
	for _, want := range []string{
		"# TYPE aggershield_requests_total counter",
		"aggershield_requests_total 7",
		"aggershield_bans_issued_total 2",
		"# TYPE aggershield_banned_ips gauge",
		"aggershield_banned_ips 3",
		"aggershield_uptime_seconds",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("metrics output missing %q\n---\n%s", want, body)
		}
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("wrong content-type %q", ct)
	}
}
