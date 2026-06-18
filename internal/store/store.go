// Package store is the storage seam. Everything above it is driver-agnostic;
// the SQLite implementation lives in store/sqlite and Postgres can slot in later
// behind the same interfaces. The seam deliberately splits the append-only log
// from the entity layer so the §2 "one rule" is enforced by which interface a
// component is handed.
package store

import (
	"context"

	"github.com/tessera/tessera/internal/entity"
	"github.com/tessera/tessera/internal/observation"
)

// ObservationLog is the append-only log (§3.1). Collectors (via observation.Sink)
// only ever get the Append capability; the reconciler additionally reads it back.
type ObservationLog interface {
	// Append writes one immutable observation and returns its assigned id.
	Append(ctx context.Context, obs observation.Observation) (id int64, err error)
	// AppendBatch writes many observations in one transaction (the buffered,
	// high-throughput write path under a busy SPAN — §M8).
	AppendBatch(ctx context.Context, obs []observation.Observation) error
	// Each streams observations in (observed_at, id) order — the canonical
	// replay order — invoking fn for each. afterID > 0 resumes after a cursor.
	Each(ctx context.Context, afterID int64, fn func(observation.Observation) error) error
	// CountObservations returns the number of rows in the log.
	CountObservations(ctx context.Context) (int64, error)
	// RecentObservations returns the newest observations (for the UI's
	// observation drill-down), most recent first.
	RecentObservations(ctx context.Context, limit int) ([]observation.Observation, error)
	// QueryObservations returns a filtered, paginated page of observations
	// (newest first) plus the total matching the filter — for the searchable
	// observations page.
	QueryObservations(ctx context.Context, f ObservationFilter) (rows []observation.Observation, total int, err error)
	// ObservationFacets returns the distinct sources and attributes present, for
	// populating the observation filter dropdowns.
	ObservationFacets(ctx context.Context) (sources, attributes []string, err error)
	// ForSubjects returns observations whose subject is in subjects, newest
	// first — the provenance trail behind an entity (§1 honest confidence).
	ForSubjects(ctx context.Context, subjects []string) ([]observation.Observation, error)
	// CompactLog collapses repeated identical observations (same source, subject,
	// attribute, and value) down to just their first and latest occurrence —
	// bounding the append-only log's growth while preserving first_seen/last_seen
	// and the reconciled result. Returns the number of rows removed (§M9).
	CompactLog(ctx context.Context) (removed int64, err error)
}

// ObservationFilter narrows and pages the observation query. Empty fields are
// ignored; Query substring-matches subject or value.
type ObservationFilter struct {
	Source    string
	Attribute string
	Query     string
	Limit     int
	Offset    int
}

// EntityStore persists the reconciled entity layer (§3.2). Only the reconciler
// writes it. ReplaceEntities is atomic (truncate + insert in one transaction),
// which is how a full replay-from-empty rebuild lands without exposing a torn
// state to readers.
type EntityStore interface {
	ReplaceEntities(ctx context.Context, snap entity.Snapshot) error
	LoadEntities(ctx context.Context) (entity.Snapshot, error)
}

// ConflictStore persists operator decisions on conflicts (which value is the
// source of truth). It is workflow state, kept separately from the derived
// conflict list and merged in at read time, keyed by (subject, attribute).
type ConflictStore interface {
	ListResolutions(ctx context.Context) ([]entity.ConflictResolution, error)
	SetResolution(ctx context.Context, r entity.ConflictResolution) error
	DeleteResolution(ctx context.Context, subject, attribute string) error
}

// Store is the full persistence surface handed to the app at startup.
type Store interface {
	ObservationLog
	EntityStore
	ConflictStore
	Migrate(ctx context.Context) error
	Close() error
}
