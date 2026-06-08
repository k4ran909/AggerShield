package proxy

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"aggershield/internal/config"
	"aggershield/internal/netutil"
)

// echoBackend reports the Host and forwarded-client headers it received.
func echoBackend(label string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Backend", label)
		_, _ = io.WriteString(w, "host="+r.Host+" xri="+r.Header.Get("X-Real-IP"))
	}))
}

func do(t *testing.T, rt *Router, host, clientIP string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "http://"+host+"/", nil)
	req.Host = host
	if clientIP != "" {
		req = req.WithContext(netutil.WithClientIP(req.Context(), clientIP))
	}
	rec := httptest.NewRecorder()
	rt.ServeHTTP(rec, req)
	return rec
}

func TestHostRoutingAndPreserveHost(t *testing.T) {
	a := echoBackend("A")
	defer a.Close()
	b := echoBackend("B")
	defer b.Close()

	cfg := &config.Config{
		Upstream: a.URL, // default/fallback
		Sites: []config.Site{
			{Host: "a.example.com", Upstream: a.URL, PreserveHost: true},
			{Host: "b.example.com", Upstream: b.URL, PreserveHost: false},
		},
	}
	rt, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}

	// a.example.com -> backend A, Host preserved.
	rec := do(t, rt, "a.example.com", "203.0.113.7")
	if rec.Header().Get("X-Backend") != "A" {
		t.Fatalf("a.example.com routed to %q, want A", rec.Header().Get("X-Backend"))
	}
	if !strings.Contains(rec.Body.String(), "host=a.example.com") {
		t.Fatalf("preserve_host=true should keep visitor Host; got %q", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "xri=203.0.113.7") {
		t.Fatalf("origin should see real client IP; got %q", rec.Body.String())
	}

	// b.example.com -> backend B, Host rewritten to the upstream's host.
	rec = do(t, rt, "b.example.com", "203.0.113.8")
	if rec.Header().Get("X-Backend") != "B" {
		t.Fatalf("b.example.com routed to %q, want B", rec.Header().Get("X-Backend"))
	}
	upstreamHost := mustHost(t, b.URL)
	if !strings.Contains(rec.Body.String(), "host="+upstreamHost) {
		t.Fatalf("preserve_host=false should rewrite Host to %q; got %q", upstreamHost, rec.Body.String())
	}

	// Unknown host -> default (A).
	rec = do(t, rt, "unknown.example.com", "203.0.113.9")
	if rec.Header().Get("X-Backend") != "A" {
		t.Fatalf("unknown host should hit default backend A, got %q", rec.Header().Get("X-Backend"))
	}
}

func TestNoOriginIsNotFound(t *testing.T) {
	cfg := &config.Config{Sites: []config.Site{{Host: "a.example.com", Upstream: "http://127.0.0.1:1"}}}
	rt, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	rec := do(t, rt, "nomatch.example.com", "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unmatched host with no default should be 404, got %d", rec.Code)
	}
}

func mustHost(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u.Host
}
