// Package collector defines the contract every signal source obeys. A collector
// runs as an independent goroutine and feeds the observation log through an
// observation.Sink — it never touches the entity tables (§2). Concrete
// collectors (passive sensor, active prober, UniFi poller, Fingerbank
// enrichment) land in M3+; this is the seam they plug into.
package collector

import (
	"context"

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
