package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTelemetryGate(t *testing.T) {
	hit := false
	h := telemetryGate("s3cret", func(w http.ResponseWriter, _ *http.Request) {
		hit = true
		w.WriteHeader(http.StatusOK)
	})

	// No token -> 401, handler not reached.
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, "/aggershield/security", nil))
	if rec.Code != http.StatusUnauthorized || hit {
		t.Fatalf("no token must be 401, got %d hit=%v", rec.Code, hit)
	}

	// Wrong token -> 401.
	rec = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/aggershield/security", nil)
	req.Header.Set("X-AggerShield-Token", "nope")
	h(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token must be 401, got %d", rec.Code)
	}

	// Correct token via header.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/aggershield/security", nil)
	req.Header.Set("X-AggerShield-Token", "s3cret")
	h(rec, req)
	if rec.Code != http.StatusOK || !hit {
		t.Fatalf("header token must pass, got %d hit=%v", rec.Code, hit)
	}

	// Correct token via query string (browser-friendly).
	hit = false
	rec = httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, "/aggershield/security?token=s3cret", nil))
	if rec.Code != http.StatusOK || !hit {
		t.Fatalf("query token must pass, got %d hit=%v", rec.Code, hit)
	}
}
