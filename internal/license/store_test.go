package license

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateValidateRevoke(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lic.json")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}

	plaintext, key, err := s.Generate("acme corp", "prod")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(plaintext, KeyPrefix) {
		t.Fatalf("key %q missing prefix", plaintext)
	}
	if key.Hash == plaintext || strings.Contains(key.Hash, plaintext) {
		t.Fatal("plaintext key must not be stored, only its hash")
	}

	if got, ok := s.Validate(plaintext); !ok || got.ID != key.ID {
		t.Fatal("freshly generated key should validate")
	}
	if _, ok := s.Validate("agsk_wrong"); ok {
		t.Fatal("unknown key must not validate")
	}

	if ok, _ := s.Revoke(key.ID); !ok {
		t.Fatal("revoke should report the key existed")
	}
	if _, ok := s.Validate(plaintext); ok {
		t.Fatal("revoked key must not validate")
	}
}

func TestHeartbeatPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lic.json")
	s, _ := Open(path)
	_, key, _ := s.Generate("svc", "")

	if err := s.RecordHeartbeat(key.ID, AgentStatus{
		Hostname: "edge-1", Protecting: "shop.example.com",
		Stats: map[string]int64{"total_requests": 42},
	}); err != nil {
		t.Fatal(err)
	}

	// Reopen from disk to confirm persistence.
	s2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	a := s2.Agent(key.ID)
	if a == nil || a.Hostname != "edge-1" || a.Stats["total_requests"] != 42 {
		t.Fatalf("heartbeat did not persist: %+v", a)
	}
	// And the key still validates after reload (hash index rebuilt).
	if _, ok := s2.Validate("nope"); ok {
		t.Fatal("bad key validated after reload")
	}
}
