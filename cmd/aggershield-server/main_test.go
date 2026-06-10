package main

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"aggershield/internal/license"
)

func testLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func newTestServer(t *testing.T) (*server, string) {
	t.Helper()
	store, err := license.Open(filepath.Join(t.TempDir(), "lic.json"))
	if err != nil {
		t.Fatal(err)
	}
	plaintext, _, err := store.Generate("test-customer", "")
	if err != nil {
		t.Fatal(err)
	}
	return &server{store: store, adminToken: "admintok", log: testLogger()}, plaintext
}

func TestValidateAndHeartbeat(t *testing.T) {
	s, key := newTestServer(t)

	// Valid key validates.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/validate", nil)
	req.Header.Set(license.HeaderKey, key)
	s.handleValidate(rec, req)
	var vr license.ValidateResp
	_ = json.NewDecoder(rec.Body).Decode(&vr)
	if rec.Code != http.StatusOK || !vr.Valid {
		t.Fatalf("valid key should validate, got %d %+v", rec.Code, vr)
	}

	// Unknown key -> 401, not valid.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/v1/validate", nil)
	req.Header.Set(license.HeaderKey, "agsk_bogus")
	s.handleValidate(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unknown key should be 401, got %d", rec.Code)
	}

	// Heartbeat records the agent.
	body := strings.NewReader(`{"hostname":"edge-1","version":"0.1.0","protecting":"shop.example.com","stats":{"total_requests":10}}`)
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/v1/heartbeat", body)
	req.Header.Set(license.HeaderKey, key)
	req.RemoteAddr = "198.51.100.9:5555"
	s.handleHeartbeat(rec, req)
	var hr license.HeartbeatResp
	_ = json.NewDecoder(rec.Body).Decode(&hr)
	if rec.Code != http.StatusOK || !hr.Licensed {
		t.Fatalf("heartbeat with valid key should be licensed, got %d %+v", rec.Code, hr)
	}
	// The agent should now show up with the server-observed source IP.
	for _, k := range s.store.Keys() {
		if a := s.store.Agent(k.ID); a != nil {
			if a.SourceIP != "198.51.100.9" || a.Hostname != "edge-1" {
				t.Fatalf("agent telemetry wrong: %+v", a)
			}
			return
		}
	}
	t.Fatal("no agent recorded after heartbeat")
}

func TestRevokedKeyHeartbeatUnlicensed(t *testing.T) {
	s, key := newTestServer(t)
	for _, k := range s.store.Keys() {
		_, _ = s.store.Revoke(k.ID)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/heartbeat", strings.NewReader("{}"))
	req.Header.Set(license.HeaderKey, key)
	s.handleHeartbeat(rec, req)
	var hr license.HeartbeatResp
	_ = json.NewDecoder(rec.Body).Decode(&hr)
	if rec.Code != http.StatusUnauthorized || hr.Licensed {
		t.Fatalf("revoked key heartbeat should be unlicensed/401, got %d %+v", rec.Code, hr)
	}
}

func TestHeartbeatPushesPolicyOnVersionChange(t *testing.T) {
	s, key := newTestServer(t)
	keyID := s.store.Keys()[0].ID
	dr := true
	if _, err := s.store.SetPolicy(keyID, &license.PolicyDoc{DryRun: &dr}); err != nil {
		t.Fatal(err)
	}

	// Agent reports version 0 -> server pushes the current policy (v1).
	hb := func(agentVer int) license.HeartbeatResp {
		body := strings.NewReader(`{"hostname":"h","policy_version":` + strconv.Itoa(agentVer) + `}`)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/heartbeat", body)
		req.Header.Set(license.HeaderKey, key)
		rec := httptest.NewRecorder()
		s.handleHeartbeat(rec, req)
		var resp license.HeartbeatResp
		_ = json.NewDecoder(rec.Body).Decode(&resp)
		return resp
	}

	r0 := hb(0)
	if r0.Policy == nil || r0.PolicyVersion != 1 || r0.Policy.DryRun == nil || !*r0.Policy.DryRun {
		t.Fatalf("agent at v0 should receive policy v1 with dry_run=true, got %+v", r0)
	}
	// Agent already at v1 -> no policy echoed back.
	r1 := hb(1)
	if r1.Policy != nil {
		t.Fatalf("agent already at v1 should not receive a policy, got %+v", r1.Policy)
	}
}

func TestAdminAuth(t *testing.T) {
	s, _ := newTestServer(t)
	h := s.adminJSON(s.handleKeysJSON)

	// No token -> 401.
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, "/api/v1/admin/keys", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("missing admin token should be 401, got %d", rec.Code)
	}
	// Correct token -> 200.
	rec = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/keys", nil)
	req.Header.Set(license.HeaderAdmin, "admintok")
	h(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("correct admin token should be 200, got %d", rec.Code)
	}
}
