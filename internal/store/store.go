// Package store is the storage seam. Everything above it is driver-agnostic;
// the SQLite implementation lives in store/sqlite and Postgres can slot in later
// behind the same interfaces. The seam deliberately splits the append-only log
// from the entity layer so the §2 "one rule" is enforced by which interface a
// component is handed.
package store

import (
	"context"
	"time"

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

// SecuritySuppressionStore persists operator acknowledgements of security
// findings (accept-risk), with a note. Workflow state, kept separately from the
// derived findings list and merged in at read time, keyed by (stable_id, proto,
// port); a zero port suppresses a host-level finding.
type SecuritySuppressionStore interface {
	ListSecuritySuppressions(ctx context.Context) ([]entity.SecuritySuppression, error)
	SetSecuritySuppression(ctx context.Context, s entity.SecuritySuppression) error
	DeleteSecuritySuppression(ctx context.Context, stableID, proto string, port int) error
}

// ForgetStore deletes all trace of a device so it can be rediscovered fresh, and
// supports age-based pruning of dormant devices. Forgetting removes the device's
// log observations (by subject) plus its workflow state (resolutions,
// suppressions) — a deliberate, admin-only departure from the append-only log,
// for cleaning up decommissioned hardware / deleted VMs.
type ForgetStore interface {
	// ForgetSubjects deletes log observations for the given subjects and the
	// host's workflow state; returns the number of observations removed.
	ForgetSubjects(ctx context.Context, stableID string, subjects []string) (removed int64, err error)
	// LastSeenBySubject returns the newest non-manual observation time per
	// subject — the "last seen on the network" signal used by auto-prune.
	LastSeenBySubject(ctx context.Context) (map[string]time.Time, error)
	// DeleteObservation removes one log row by id (surgical artifact removal).
	DeleteObservation(ctx context.Context, id int64) (removed int64, err error)
	// DeleteObservations removes log rows matching a filter (e.g. all bindings of
	// one IP, or a single host's open-port). At least one filter field must be set.
	DeleteObservations(ctx context.Context, f ObsDeleteFilter) (removed int64, err error)
}

// ObsDeleteFilter selects observations to delete; set fields are AND-combined,
// and at least one must be non-empty (deleting the whole log is refused).
type ObsDeleteFilter struct {
	Subject     string // exact subject
	Attribute   string // exact attribute
	Value       string // exact value
	ValuePrefix string // value LIKE prefix% (e.g. "tcp/443|" for a port's banners)
}

func (f ObsDeleteFilter) Empty() bool {
	return f.Subject == "" && f.Attribute == "" && f.Value == "" && f.ValuePrefix == ""
}

// AvailabilityStore persists device online/offline history (one row per
// transition) for uptime reporting.
type AvailabilityStore interface {
	// LatestAvailability returns the most recent online state per stable_id.
	LatestAvailability(ctx context.Context) (map[string]bool, error)
	// AppendAvailability records new transition events.
	AppendAvailability(ctx context.Context, events []entity.AvailabilityEvent) error
	// AvailabilityForHost returns a host's transition events, oldest first.
	AvailabilityForHost(ctx context.Context, stableID string) ([]entity.AvailabilityEvent, error)
}

// MergeStore persists operator "these hosts are the same device" links, folded
// into reconciliation by canonicalizing host keys.
type MergeStore interface {
	ListMerges(ctx context.Context) ([]entity.HostMerge, error)
	SetMerge(ctx context.Context, m entity.HostMerge) error
	DeleteMerge(ctx context.Context, secondary string) error
}

// PrecedenceStore persists the source-precedence policy (attribute → preferred
// source), folded into reconciliation.
type PrecedenceStore interface {
	ListPrecedence(ctx context.Context) ([]entity.SourcePrecedence, error)
	SetPrecedence(ctx context.Context, p entity.SourcePrecedence) error
	DeletePrecedence(ctx context.Context, attribute string) error
}

// Store is the full persistence surface handed to the app at startup.
type Store interface {
	ObservationLog
	EntityStore
	ConflictStore
	SecuritySuppressionStore
	ForgetStore
	AvailabilityStore
	MergeStore
	PrecedenceStore
	Migrate(ctx context.Context) error
	Close() error
}
