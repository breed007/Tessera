package passive

import (
	"hash/fnv"
	"time"
)

// deduper drops duplicate frames seen within a short window. A SPAN/mirror port
// configured for both ingress and egress delivers each frame twice; without
// dedup every mirrored frame would be parsed and emitted twice (§4.1). The key
// is a hash of the whole frame, so byte-identical duplicates collapse.
type deduper struct {
	window    time.Duration
	seen      map[uint64]time.Time
	lastClean time.Time
}

func newDeduper(window time.Duration) *deduper {
	if window <= 0 {
		window = 50 * time.Millisecond
	}
	return &deduper{window: window, seen: make(map[uint64]time.Time)}
}

// duplicate reports whether data was already seen within the window. It records
// the frame either way (refreshing the timestamp) and opportunistically evicts
// stale entries so the map can't grow without bound on a busy link.
func (d *deduper) duplicate(data []byte, now time.Time) bool {
	h := fnv.New64a()
	_, _ = h.Write(data)
	k := h.Sum64()

	t, ok := d.seen[k]
	d.seen[k] = now
	dup := ok && now.Sub(t) <= d.window

	d.maybeClean(now)
	return dup
}

func (d *deduper) maybeClean(now time.Time) {
	if now.Sub(d.lastClean) < d.window {
		return
	}
	for k, t := range d.seen {
		if now.Sub(t) > d.window {
			delete(d.seen, k)
		}
	}
	d.lastClean = now
}
