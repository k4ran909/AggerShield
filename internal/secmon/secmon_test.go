package secmon

import (
	"testing"
	"time"
)

// driver lets a test feed cumulative counters deterministically.
type driver struct{ c Counters }

func (d *driver) snap() Counters { return d.c }

func newTestMonitor(d *driver, threshold int64, exit int) *Monitor {
	return New(time.Second, 100, threshold, exit, d.snap)
}

func TestSamplesAreDeltas(t *testing.T) {
	d := &driver{}
	m := newTestMonitor(d, 20, 3)
	base := time.Now()

	m.tick(base) // seed baseline, no sample
	d.c = Counters{Total: 10, Allowed: 9, Blocked: 1, Challenged: 0, Bans: 0}
	m.tick(base.Add(time.Second))
	d.c = Counters{Total: 30, Allowed: 25, Blocked: 5, Challenged: 2, Bans: 1}
	m.tick(base.Add(2 * time.Second))

	s := m.Samples()
	if len(s) != 2 {
		t.Fatalf("expected 2 samples (first tick seeds), got %d", len(s))
	}
	if s[0].Reqs != 10 || s[0].Blocked != 1 {
		t.Fatalf("first delta wrong: %+v", s[0])
	}
	if s[1].Reqs != 20 || s[1].Blocked != 4 || s[1].Bans != 1 {
		t.Fatalf("second delta wrong: %+v", s[1])
	}
}

func TestAttackEventOpensAndCloses(t *testing.T) {
	d := &driver{}
	m := newTestMonitor(d, 20, 2) // open at >=20 blocked/iv, close after 2 calm
	base := time.Now()
	m.tick(base) // seed

	step := func(addBlocked int64, at int) {
		d.c.Total += 100
		d.c.Blocked += addBlocked
		m.tick(base.Add(time.Duration(at) * time.Second))
	}

	step(2, 1) // calm
	if m.State() != "normal" {
		t.Fatal("should start normal")
	}
	step(50, 2) // spike -> attack opens
	if m.State() != "under_attack" {
		t.Fatal("a block spike should open an attack event")
	}
	step(60, 3) // still attacking
	step(0, 4)  // calm 1
	step(0, 5)  // calm 2 -> closes
	if m.State() != "normal" {
		t.Fatalf("event should close after %d calm intervals", 2)
	}

	ev := m.Events()
	if len(ev) != 1 {
		t.Fatalf("expected 1 recorded event, got %d", len(ev))
	}
	if ev[0].Ongoing() {
		t.Fatal("event should be closed")
	}
	if ev[0].PeakBlocked != 60 {
		t.Fatalf("peak blocked should be 60, got %d", ev[0].PeakBlocked)
	}
	if ev[0].TotalBlocked != 110 { // 50 + 60
		t.Fatalf("total blocked should be 110, got %d", ev[0].TotalBlocked)
	}
}

func TestRingIsBounded(t *testing.T) {
	d := &driver{}
	m := New(time.Second, 10, 9999, 5, d.snap) // retain only 10
	base := time.Now()
	for i := 0; i < 25; i++ {
		d.c.Total += 1
		m.tick(base.Add(time.Duration(i) * time.Second))
	}
	if got := len(m.Samples()); got > 10 {
		t.Fatalf("ring should be capped at 10, got %d", got)
	}
}
