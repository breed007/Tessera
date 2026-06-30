// Package reconcile folds the append-only observation log into the reconciled
// entity layer (§3.3). It is the ONLY component that reads the log and writes
// entities.
//
// The engine implements the §3.3 rules: MAC-primary identity resolution with
// provisional IP hosts that fold into their owner MAC (incl. randomized-MAC
// handling, §6); confidence-weighting with recency decay and source-priority
// tiers as the tiebreak; manual annotations are authoritative; disagreements on
// high-value attributes are recorded as conflicts rather than silently resolved;
// and addresses age active→stale→free as their newest supporting observation
// ages out. The whole entity layer is reconstructable by replaying the log from
// empty — a single Rebuild does exactly that.
package reconcile

import (
	"context"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/tessera/tessera/internal/entity"
	"github.com/tessera/tessera/internal/observation"
	"github.com/tessera/tessera/internal/store"
)

// Params are the reconciliation thresholds (§3.3), normally sourced from config.
type Params struct {
	StaleAfter         time.Duration    // address active→stale boundary
	FreeAfter          time.Duration    // address stale→free boundary
	ConfidenceHalfLife time.Duration    // confidence halves every half-life of age
	Now                func() time.Time // injectable clock; nil → time.Now
}

// DefaultParams returns the §5 defaults.
func DefaultParams() Params {
	return Params{
		StaleAfter:         24 * time.Hour,
		FreeAfter:          168 * time.Hour,
		ConfidenceHalfLife: 72 * time.Hour,
	}
}

func (p Params) normalized() Params {
	if p.StaleAfter <= 0 {
		p.StaleAfter = 24 * time.Hour
	}
	if p.FreeAfter <= 0 {
		p.FreeAfter = 168 * time.Hour
	}
	if p.ConfidenceHalfLife <= 0 {
		p.ConfidenceHalfLife = 72 * time.Hour
	}
	if p.Now == nil {
		p.Now = time.Now
	}
	return p
}

// Reconciler rebuilds the entity layer from the log.
type Reconciler struct {
	store  store.Store
	log    *slog.Logger
	params Params
	mu     sync.Mutex // serializes Rebuild (background loop + API-triggered rebuilds)
}

// New returns a Reconciler. params may be the zero value; missing thresholds
// fall back to the §5 defaults.
func New(st store.Store, log *slog.Logger, params Params) *Reconciler {
	if log == nil {
		log = slog.Default()
	}
	return &Reconciler{store: st, log: log, params: params.normalized()}
}

// Stats summarizes a rebuild.
type Stats struct {
	Observations int64
	Hosts        int
	Interfaces   int
	Addresses    int
	Conflicts    int
}

// Rebuild replays the entire log from empty and atomically replaces the entity
// layer. Two passes: pass 1 resolves current IP→MAC ownership; pass 2 folds
// every observation onto its canonical host. now is captured once so the
// reconciliation is internally consistent.
func (r *Reconciler) Rebuild(ctx context.Context) (Stats, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	eng := newEngine(r.params.Now().UTC(), r.params)

	// Operator merge links fold one host identity into another (§ host merge).
	if merges, err := r.store.ListMerges(ctx); err != nil {
		return Stats{}, err
	} else {
		for _, m := range merges {
			eng.merges[m.Secondary] = m.Primary
		}
	}

	// Pass 1: ip_binding ownership.
	if err := r.store.Each(ctx, 0, func(obs observation.Observation) error {
		eng.observeBinding(obs)
		return nil
	}); err != nil {
		return Stats{}, err
	}
	// Pass 2: fold all observations.
	if err := r.store.Each(ctx, 0, func(obs observation.Observation) error {
		eng.apply(obs)
		return nil
	}); err != nil {
		return Stats{}, err
	}

	snap, conflicts := eng.snapshot()
	snap.Conflicts = toConflicts(conflicts)

	if err := r.store.ReplaceEntities(ctx, snap); err != nil {
		return Stats{}, err
	}

	count, err := r.store.CountObservations(ctx)
	if err != nil {
		return Stats{}, err
	}
	stats := Stats{
		Observations: count,
		Hosts:        len(snap.Hosts),
		Interfaces:   len(snap.Interfaces),
		Addresses:    len(snap.Addresses),
		Conflicts:    len(snap.Conflicts),
	}
	r.log.Info("reconcile rebuild complete",
		"observations", stats.Observations,
		"hosts", stats.Hosts,
		"interfaces", stats.Interfaces,
		"addresses", stats.Addresses,
		"conflicts", stats.Conflicts)
	return stats, nil
}

// toConflicts converts the engine's internal conflict records into entity rows
// with deterministic ids (sorted by subject then attribute).
func toConflicts(recs []conflictRec) []entity.Conflict {
	sort.SliceStable(recs, func(i, j int) bool {
		if recs[i].subject != recs[j].subject {
			return recs[i].subject < recs[j].subject
		}
		return recs[i].attribute < recs[j].attribute
	})
	out := make([]entity.Conflict, 0, len(recs))
	for i, c := range recs {
		out = append(out, entity.Conflict{
			ID:        int64(i + 1),
			Subject:   c.subject,
			Attribute: c.attribute,
			ValueA:    c.valueA,
			SourceA:   c.sourceA,
			CountA:    c.countA,
			LastSeenA: c.lastA,
			ValueB:    c.valueB,
			SourceB:   c.sourceB,
			CountB:    c.countB,
			LastSeenB: c.lastB,
			OpenedAt:  c.openedAt,
			Resolved:  false,
		})
	}
	return out
}
