// Package collector defines the contract every signal source obeys. A collector
// runs as an independent goroutine and feeds the observation log through an
// observation.Sink — it never touches the entity tables (§2). Concrete
// collectors (passive sensor, active prober, UniFi poller, Fingerbank
// enrichment) land in M3+; this is the seam they plug into.
package collector

import (
	"context"
	"sync"
	"time"

	"github.com/tessera/tessera/internal/observation"
)

// Collector is a long-running signal source. Run blocks until ctx is cancelled
// and must return promptly on cancellation. Per §10, a collector recovers any
// panic at its own edge — no panic crosses the goroutine boundary into the app.
type Collector interface {
	// Name identifies the collector for logging and as the basis of its
	// collector_id.
	Name() string
	// Run executes the collection loop, emitting observations via sink, until
	// ctx is cancelled.
	Run(ctx context.Context, sink *observation.Sink) error
}

// Status is a collector's last-known connection/run health, surfaced in the UI.
// State is "ok" (last cycle succeeded), "error" (last cycle failed), or "idle"
// (configured but nothing conclusive has run yet).
type Status struct {
	Name    string    `json:"name"`
	State   string    `json:"state"`
	LastRun time.Time `json:"last_run,omitempty"`
	Detail  string    `json:"detail,omitempty"`
	Err     string    `json:"err,omitempty"`
}

// Reporter is implemented by collectors that publish a Status (UniFi, Fingerbank).
type Reporter interface{ Status() Status }

// Health is a concurrency-safe last-run tracker a collector embeds and exposes
// via Status(). It satisfies Reporter.
type Health struct {
	name string
	mu   sync.Mutex
	st   Status
}

// NewHealth returns a tracker in the "idle" state with an optional detail.
func NewHealth(name, detail string) *Health {
	return &Health{name: name, st: Status{Name: name, State: "idle", Detail: detail}}
}

// Success records a healthy cycle with a human-readable detail.
func (h *Health) Success(detail string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.st = Status{Name: h.name, State: "ok", LastRun: time.Now(), Detail: detail}
}

// Failure records a failed cycle.
func (h *Health) Failure(err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.st = Status{Name: h.name, State: "error", LastRun: time.Now(), Err: err.Error()}
}

// Status returns the current snapshot (Reporter).
func (h *Health) Status() Status {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.st
}
