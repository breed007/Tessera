package api

import (
	"time"

	"github.com/breed007/Tessera/internal/entity"
)

// AvailabilityView is a host's uptime summary for its detail page.
type AvailabilityView struct {
	Online    bool                       `json:"online"`
	Since     time.Time                  `json:"since"`       // when the current state began
	Uptime24h float64                    `json:"uptime_24h"`  // 0–1, or -1 if unknown
	Uptime7d  float64                    `json:"uptime_7d"`   // 0–1, or -1
	Uptime30d float64                    `json:"uptime_30d"`  // 0–1, or -1
	Events    []entity.AvailabilityEvent `json:"events"`      // recent transitions, newest first
}

const availabilityEventCap = 20

// buildAvailability summarizes a host's transition events (oldest first) into an
// uptime view as of `now`. Returns nil if there's no history yet.
func buildAvailability(events []entity.AvailabilityEvent, now time.Time) *AvailabilityView {
	if len(events) == 0 {
		return nil
	}
	last := events[len(events)-1]
	av := &AvailabilityView{
		Online:    last.Online,
		Since:     last.At,
		Uptime24h: uptimeRatio(events, now.Add(-24*time.Hour), now),
		Uptime7d:  uptimeRatio(events, now.Add(-7*24*time.Hour), now),
		Uptime30d: uptimeRatio(events, now.Add(-30*24*time.Hour), now),
	}
	// Recent transitions, newest first, capped.
	n := len(events)
	if n > availabilityEventCap {
		events = events[n-availabilityEventCap:]
	}
	av.Events = make([]entity.AvailabilityEvent, 0, len(events))
	for i := len(events) - 1; i >= 0; i-- {
		e := events[i]
		e.StableID = "" // redundant on the detail page
		av.Events = append(av.Events, e)
	}
	return av
}

// uptimeRatio returns the fraction of [winStart, now] the host was online, from
// its transition events (oldest first). The window is clamped to start no earlier
// than the first recorded event (we don't count time before the device was
// known). Returns -1 when there's no overlap to measure.
func uptimeRatio(events []entity.AvailabilityEvent, winStart, now time.Time) float64 {
	if len(events) == 0 || !now.After(winStart) {
		return -1
	}
	start := winStart
	if events[0].At.After(start) {
		start = events[0].At
	}
	if !now.After(start) {
		return -1
	}
	state := events[0].Online // baseline at `start`
	cursor := start
	var online time.Duration
	for _, e := range events {
		if !e.At.After(start) { // event at/before window start: just update baseline
			state = e.Online
			continue
		}
		t := e.At
		if t.After(now) {
			t = now
		}
		if t.After(cursor) {
			if state {
				online += t.Sub(cursor)
			}
			cursor = t
		}
		state = e.Online
		if !e.At.Before(now) {
			break
		}
	}
	if now.After(cursor) && state {
		online += now.Sub(cursor)
	}
	total := now.Sub(start)
	if total <= 0 {
		return -1
	}
	r := online.Seconds() / total.Seconds()
	if r < 0 {
		r = 0
	}
	if r > 1 {
		r = 1
	}
	return r
}
