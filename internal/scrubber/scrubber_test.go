package scrubber

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"aggershield/internal/config"
)

func quietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestWebhookEngageDisengage(t *testing.T) {
	var got []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var m map[string]any
		_ = json.NewDecoder(r.Body).Decode(&m)
		got = append(got, m)
	}))
	defer srv.Close()

	s := New(config.Scrubber{Enabled: true, Provider: "webhook", WebhookURL: srv.URL}, quietLog())
	if s == nil || s.Name() != "webhook" {
		t.Fatalf("expected webhook scrubber, got %v", s)
	}
	if err := s.Engage(context.Background(), "flood"); err != nil {
		t.Fatal(err)
	}
	if err := s.Disengage(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0]["action"] != "engage" || got[1]["action"] != "disengage" {
		t.Fatalf("webhook payloads wrong: %+v", got)
	}
	if got[0]["reason"] != "flood" {
		t.Fatalf("engage reason not forwarded: %+v", got[0])
	}
}

func TestCloudflareSetsSecurityLevel(t *testing.T) {
	type req struct {
		path, auth, value string
	}
	var reqs []req
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		reqs = append(reqs, req{r.URL.Path, r.Header.Get("Authorization"), body["value"]})
		if r.Method != http.MethodPatch {
			t.Errorf("expected PATCH, got %s", r.Method)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"success":true}`)
	}))
	defer srv.Close()

	s := New(config.Scrubber{
		Enabled:  true,
		Provider: "cloudflare",
		Cloudflare: config.CloudflareScrub{
			APIToken: "tok123", ZoneID: "zoneABC", APIBase: srv.URL, NormalLevel: "high",
		},
	}, quietLog())

	if err := s.Engage(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	if err := s.Disengage(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(reqs) != 2 {
		t.Fatalf("expected 2 cloudflare calls, got %d", len(reqs))
	}
	if reqs[0].value != "under_attack" || reqs[1].value != "high" {
		t.Fatalf("security levels wrong: %+v", reqs)
	}
	if reqs[0].auth != "Bearer tok123" {
		t.Fatalf("auth header wrong: %q", reqs[0].auth)
	}
	if reqs[0].path != "/zones/zoneABC/settings/security_level" {
		t.Fatalf("path wrong: %q", reqs[0].path)
	}
}

func TestUpstreamErrorSurfaced(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusForbidden)
	}))
	defer srv.Close()
	s := New(config.Scrubber{Enabled: true, Provider: "webhook", WebhookURL: srv.URL}, quietLog())
	if err := s.Engage(context.Background(), "x"); err == nil {
		t.Fatal("a non-2xx upstream response should surface an error")
	}
}

func TestDisabledReturnsNil(t *testing.T) {
	if s := New(config.Scrubber{Enabled: false}, quietLog()); s != nil {
		t.Fatal("disabled scrubber should be nil")
	}
}
