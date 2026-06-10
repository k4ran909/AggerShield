package banlist

import (
	"path/filepath"
	"testing"
	"time"
)

func TestPersistenceSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bans.json")

	s1 := New(time.Minute, time.Hour, 2.0, time.Hour, 1000, nil)
	if err := s1.EnablePersistence(path, time.Hour); err != nil { // long interval; we snapshot manually
		t.Fatal(err)
	}
	s1.BanFor("203.0.113.7", 10*time.Minute)
	if err := s1.snapshot(); err != nil {
		t.Fatal(err)
	}
	s1.Close()

	// A fresh store loading the same file should still have the ban.
	s2 := New(time.Minute, time.Hour, 2.0, time.Hour, 1000, nil)
	defer s2.Close()
	if err := s2.EnablePersistence(path, time.Hour); err != nil {
		t.Fatal(err)
	}
	if !s2.IsBanned("203.0.113.7") {
		t.Fatal("ban should survive a restart via persistence")
	}
}

func TestPersistenceDropsExpired(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bans.json")
	s1 := New(time.Minute, time.Hour, 2.0, time.Hour, 1000, nil)
	_ = s1.EnablePersistence(path, time.Hour)
	s1.BanFor("198.51.100.9", time.Millisecond)
	_ = s1.snapshot()
	s1.Close()
	time.Sleep(5 * time.Millisecond)

	s2 := New(time.Minute, time.Hour, 2.0, time.Hour, 1000, nil)
	defer s2.Close()
	_ = s2.EnablePersistence(path, time.Hour)
	if s2.IsBanned("198.51.100.9") {
		t.Fatal("expired bans must not be restored")
	}
}

func TestDrainRecentAndFleetEcho(t *testing.T) {
	s := New(time.Minute, time.Hour, 2.0, time.Hour, 1000, nil)
	defer s.Close()

	s.Ban("203.0.113.1")
	s.BanFor("203.0.113.2", time.Minute)
	// Fleet-applied bans must NOT show up in the recent buffer (no echo loop).
	s.BanFleet("203.0.113.99", time.Minute)

	recent := s.DrainRecent()
	if len(recent) != 2 {
		t.Fatalf("expected 2 locally-banned IPs to report, got %v", recent)
	}
	// Draining again yields nothing.
	if r := s.DrainRecent(); r != nil {
		t.Fatalf("recent should be empty after drain, got %v", r)
	}
	// The fleet-applied IP is still banned locally though.
	if !s.IsBanned("203.0.113.99") {
		t.Fatal("BanFleet should still ban the IP")
	}
}
