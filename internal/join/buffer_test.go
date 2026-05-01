package join

import (
	"testing"
	"time"
)

func TestBuffer_AppendAndDrain(t *testing.T) {
	b := NewBuffer(10, 60*time.Second, time.Now)
	b.Append("uid1", Pending{RuleID: "942100", Severity: "CRITICAL", Hostname: "h"})
	b.Append("uid1", Pending{RuleID: "920350", Severity: "WARNING", Hostname: "h"})

	got := b.Drain("uid1")
	if len(got) != 2 {
		t.Fatalf("got %d, want 2", len(got))
	}
	if got[0].RuleID != "942100" || got[1].RuleID != "920350" {
		t.Fatalf("order broken: %+v", got)
	}

	if again := b.Drain("uid1"); len(again) != 0 {
		t.Fatalf("second drain should be empty, got %d", len(again))
	}
}

func TestBuffer_TTLEviction(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	clock := func() time.Time { return now }
	b := NewBuffer(10, 30*time.Second, clock)

	b.Append("old", Pending{RuleID: "1"})
	now = now.Add(31 * time.Second)
	b.Append("new", Pending{RuleID: "2"})

	expired := b.SweepExpired()
	if len(expired) != 1 {
		t.Fatalf("expected 1 orphan, got %d", len(expired))
	}
	if expired[0].UniqueID != "old" {
		t.Fatalf("wrong orphan: %s", expired[0].UniqueID)
	}

	if got := b.Drain("new"); len(got) != 1 {
		t.Fatalf("new entry survived? got %d", len(got))
	}
	if got := b.Size(); got != 0 {
		t.Fatalf("buffer should be empty, got size %d", got)
	}
}

func TestBuffer_OverflowEvictsOldest(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	clock := func() time.Time { now = now.Add(time.Millisecond); return now }
	b := NewBuffer(2, 10*time.Minute, clock)

	b.Append("a", Pending{RuleID: "1"})
	b.Append("b", Pending{RuleID: "2"})
	b.Append("c", Pending{RuleID: "3"})

	if got := b.Size(); got != 2 {
		t.Fatalf("size = %d, want 2", got)
	}
	if drops := b.OrphansEvicted(); drops != 1 {
		t.Fatalf("orphans evicted = %d, want 1", drops)
	}
	if d := b.Drain("a"); len(d) != 0 {
		t.Fatalf("'a' should have been evicted, got %d", len(d))
	}
	if d := b.Drain("b"); len(d) != 1 {
		t.Fatalf("'b' should still be present, got %d", len(d))
	}
}
