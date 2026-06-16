package sqlite

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/tessera/tessera/internal/observation"
)

func TestCompactLog(t *testing.T) {
	ctx := context.Background()
	st, err := Open(filepath.Join(t.TempDir(), "c.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}

	t0 := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	add := func(subj, val string, off time.Duration) {
		_, err := st.Append(ctx, observation.Observation{
			ObservedAt: t0.Add(off), Source: observation.SourceUniFi, CollectorID: "unifi",
			SubjectType: observation.SubjectMAC, Subject: subj, Attribute: observation.AttrIPBinding,
			Value: val, Confidence: 90,
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	// A poller re-emitting the same binding 5×, plus a changed value, plus a
	// different subject. The 5 identical rows should collapse to first + last.
	for i := 0; i < 5; i++ {
		add("aa:bb:cc:00:00:01", "10.0.0.5", time.Duration(i)*time.Minute)
	}
	add("aa:bb:cc:00:00:01", "10.0.0.9", 10*time.Minute) // different value → kept
	add("aa:bb:cc:00:00:02", "10.0.0.6", 0)              // different subject → kept

	before, _ := st.CountObservations(ctx)
	removed, err := st.CompactLog(ctx)
	if err != nil {
		t.Fatal(err)
	}
	after, _ := st.CountObservations(ctx)

	// Started with 7; the 5-identical group collapses to 2 → remove 3.
	if removed != 3 {
		t.Errorf("removed = %d, want 3", removed)
	}
	if before-after != 3 {
		t.Errorf("count delta = %d, want 3", before-after)
	}

	// The earliest (first_seen) and latest occurrence of the collapsed group must
	// survive; the changed value and other subject untouched.
	obs, _ := st.ForSubjects(ctx, []string{"aa:bb:cc:00:00:01"})
	var firstSeen, lastSeen time.Time
	bindings := 0
	for _, o := range obs {
		if o.Value == "10.0.0.5" {
			bindings++
			if firstSeen.IsZero() || o.ObservedAt.Before(firstSeen) {
				firstSeen = o.ObservedAt
			}
			if o.ObservedAt.After(lastSeen) {
				lastSeen = o.ObservedAt
			}
		}
	}
	if bindings != 2 {
		t.Errorf("collapsed group has %d rows, want 2 (first + last)", bindings)
	}
	if !firstSeen.Equal(t0) {
		t.Errorf("first occurrence (first_seen) lost: %v", firstSeen)
	}
	if !lastSeen.Equal(t0.Add(4 * time.Minute)) {
		t.Errorf("last occurrence lost: %v", lastSeen)
	}

	// Compaction is idempotent — a second pass removes nothing.
	if again, _ := st.CompactLog(ctx); again != 0 {
		t.Errorf("second compaction removed %d, want 0", again)
	}
}
