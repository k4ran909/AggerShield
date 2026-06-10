package license

import (
	"path/filepath"
	"testing"
	"time"
)

func TestFleetBlocklistVersioning(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "lic.json"))
	if err != nil {
		t.Fatal(err)
	}

	ips, ver := s.FleetBlocklist()
	if len(ips) != 0 || ver != 0 {
		t.Fatalf("empty store should give no blocklist, got %v v%d", ips, ver)
	}

	// Adding new IPs bumps the version.
	_ = s.AddFleetBans([]string{"1.1.1.1", "2.2.2.2"}, time.Hour, 100)
	ips, ver = s.FleetBlocklist()
	if len(ips) != 2 || ver != 1 {
		t.Fatalf("after add: got %v v%d, want 2 ips v1", ips, ver)
	}

	// Re-reporting an existing IP (refresh) must NOT bump the version.
	_ = s.AddFleetBans([]string{"1.1.1.1"}, time.Hour, 100)
	_, ver2 := s.FleetBlocklist()
	if ver2 != 1 {
		t.Fatalf("refreshing an existing IP should not bump version, got v%d", ver2)
	}

	// A genuinely new IP bumps it again.
	_ = s.AddFleetBans([]string{"3.3.3.3"}, time.Hour, 100)
	_, ver3 := s.FleetBlocklist()
	if ver3 != 2 {
		t.Fatalf("a new IP should bump version to 2, got v%d", ver3)
	}
}

func TestFleetBlocklistExpiry(t *testing.T) {
	s, _ := Open(filepath.Join(t.TempDir(), "lic.json"))
	_ = s.AddFleetBans([]string{"9.9.9.9"}, time.Millisecond, 100)
	time.Sleep(5 * time.Millisecond)
	ips, _ := s.FleetBlocklist()
	if len(ips) != 0 {
		t.Fatalf("expired fleet bans should be swept, got %v", ips)
	}
}

func TestFleetBlocklistCap(t *testing.T) {
	s, _ := Open(filepath.Join(t.TempDir(), "lic.json"))
	_ = s.AddFleetBans([]string{"1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"}, time.Hour, 2)
	ips, _ := s.FleetBlocklist()
	if len(ips) > 2 {
		t.Fatalf("blocklist should be capped at 2, got %d", len(ips))
	}
}
