package api

import (
	"math"
	"testing"
	"time"

	"github.com/breed007/Tessera/internal/entity"
)

func TestUptimeRatio(t *testing.T) {
	now := time.Date(2026, 1, 10, 12, 0, 0, 0, time.UTC)
	ev := func(online bool, ago time.Duration) entity.AvailabilityEvent {
		return entity.AvailabilityEvent{Online: online, At: now.Add(-ago)}
	}
	approx := func(got, want float64) bool {
		if want < 0 {
			return got < 0
		}
		return math.Abs(got-want) < 0.01
	}

	cases := []struct {
		name   string
		events []entity.AvailabilityEvent
		win    time.Duration
		want   float64
	}{
		{"always online", []entity.AvailabilityEvent{ev(true, 48*time.Hour)}, 24 * time.Hour, 1.0},
		{"always offline", []entity.AvailabilityEvent{ev(false, 48*time.Hour)}, 24 * time.Hour, 0.0},
		{"down half the window", []entity.AvailabilityEvent{ev(true, 48 * time.Hour), ev(false, 12 * time.Hour)}, 24 * time.Hour, 0.5},
		{"came up midway", []entity.AvailabilityEvent{ev(false, 48 * time.Hour), ev(true, 6 * time.Hour)}, 24 * time.Hour, 0.25},
		{"no events", nil, 24 * time.Hour, -1},
		// History shorter than the window: clamp to first event (online for the whole known period).
		{"short history online", []entity.AvailabilityEvent{ev(true, 2 * time.Hour)}, 30 * 24 * time.Hour, 1.0},
	}
	for _, c := range cases {
		got := uptimeRatio(c.events, now.Add(-c.win), now)
		if !approx(got, c.want) {
			t.Errorf("%s: uptimeRatio = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestBuildAvailability(t *testing.T) {
	now := time.Date(2026, 1, 10, 12, 0, 0, 0, time.UTC)
	if buildAvailability(nil, now) != nil {
		t.Fatal("no events should yield nil view")
	}
	events := []entity.AvailabilityEvent{
		{Online: true, At: now.Add(-50 * time.Hour)},
		{Online: false, At: now.Add(-2 * time.Hour)},
	}
	av := buildAvailability(events, now)
	if av.Online {
		t.Errorf("current state should be offline (last event)")
	}
	if !av.Since.Equal(now.Add(-2 * time.Hour)) {
		t.Errorf("since = %v, want last transition", av.Since)
	}
	if len(av.Events) != 2 || av.Events[0].Online != false {
		t.Errorf("events should be newest-first: %+v", av.Events)
	}
	if av.Uptime24h < 0 || av.Uptime24h >= 1 {
		t.Errorf("uptime_24h = %v, want partial (down for last 2h of 24h)", av.Uptime24h)
	}
}
