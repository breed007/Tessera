// Package sqlite implements the storage seam (store.Store) on pure-Go SQLite
// (modernc.org/sqlite — no cgo, so Tessera stays a single static binary).
package sqlite

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"strings"
	"time"

	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver

	"github.com/tessera/tessera/internal/entity"
	"github.com/tessera/tessera/internal/observation"
	"github.com/tessera/tessera/internal/store"
)

//go:embed migrations/*.up.sql
var migrationsFS embed.FS

const rfc3339ms = "2006-01-02T15:04:05.000Z07:00"

// Store is the SQLite-backed implementation of store.Store.
type Store struct {
	db *sql.DB
}

// Open opens (creating if needed) a SQLite database at dsn and configures the
// pragmas Tessera relies on: WAL for concurrent read during the reconcile
// write, enforced foreign keys, and a busy timeout so the append path and the
// reconcile transaction don't trip over each other under load.
func Open(dsn string) (*Store, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlite: open %q: %w", dsn, err)
	}
	// SQLite is single-writer; serialize writes and keep one long-lived conn pool.
	db.SetMaxOpenConns(1)
	pragmas := []string{
		"PRAGMA journal_mode = WAL",
		"PRAGMA foreign_keys = ON",
		"PRAGMA busy_timeout = 5000",
		"PRAGMA synchronous = NORMAL",
	}
	for _, p := range pragmas {
		if _, err := db.Exec(p); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("sqlite: %s: %w", p, err)
		}
	}
	return &Store{db: db}, nil
}

// Migrate applies the embedded schema migrations (§3).
func (s *Store) Migrate(ctx context.Context) error {
	sub, err := fs.Sub(migrationsFS, "migrations")
	if err != nil {
		return fmt.Errorf("sqlite: sub migrations fs: %w", err)
	}
	return store.RunMigrations(ctx, s.db, sub)
}

func (s *Store) Close() error { return s.db.Close() }

// ── ObservationLog ───────────────────────────────────────────────────────────

// Append writes one immutable observation and returns its assigned id.
func (s *Store) Append(ctx context.Context, obs observation.Observation) (int64, error) {
	if err := obs.Validate(); err != nil {
		return 0, err
	}
	var raw any
	if len(obs.Raw) > 0 {
		raw = string(obs.Raw)
	}
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO observations
			(observed_at, source, collector_id, subject_type, subject, attribute, value, confidence, raw)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		obs.ObservedAt.UTC().Format(rfc3339ms),
		string(obs.Source), obs.CollectorID, string(obs.SubjectType),
		obs.Subject, string(obs.Attribute), obs.Value, obs.Confidence, raw,
	)
	if err != nil {
		return 0, fmt.Errorf("sqlite: append observation: %w", err)
	}
	return res.LastInsertId()
}

// AppendBatch inserts many observations in a single transaction. Invalid rows
// are skipped (logged by the caller's flush path) rather than failing the batch.
func (s *Store) AppendBatch(ctx context.Context, batch []observation.Observation) error {
	if len(batch) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("sqlite: begin batch: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op after Commit
	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO observations
			(observed_at, source, collector_id, subject_type, subject, attribute, value, confidence, raw)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("sqlite: prepare batch: %w", err)
	}
	defer stmt.Close()
	for _, obs := range batch {
		if err := obs.Validate(); err != nil {
			continue // skip malformed rather than abort the batch
		}
		var raw any
		if len(obs.Raw) > 0 {
			raw = string(obs.Raw)
		}
		if _, err := stmt.ExecContext(ctx,
			obs.ObservedAt.UTC().Format(rfc3339ms), string(obs.Source), obs.CollectorID,
			string(obs.SubjectType), obs.Subject, string(obs.Attribute), obs.Value, obs.Confidence, raw,
		); err != nil {
			return fmt.Errorf("sqlite: batch insert: %w", err)
		}
	}
	return tx.Commit()
}

// Each streams observations in (observed_at, id) order — the canonical replay
// order used by the reconciler.
func (s *Store) Each(ctx context.Context, afterID int64, fn func(observation.Observation) error) error {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, observed_at, source, collector_id, subject_type, subject, attribute, value, confidence, raw
		FROM observations
		WHERE id > ?
		ORDER BY observed_at ASC, id ASC`, afterID)
	if err != nil {
		return fmt.Errorf("sqlite: query observations: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var (
			obs       observation.Observation
			observed  string
			src, styp string
			attr      string
			raw       sql.NullString
		)
		if err := rows.Scan(&obs.ID, &observed, &src, &obs.CollectorID, &styp,
			&obs.Subject, &attr, &obs.Value, &obs.Confidence, &raw); err != nil {
			return fmt.Errorf("sqlite: scan observation: %w", err)
		}
		t, err := parseTime(observed)
		if err != nil {
			return err
		}
		obs.ObservedAt = t
		obs.Source = observation.Source(src)
		obs.SubjectType = observation.SubjectType(styp)
		obs.Attribute = observation.Attribute(attr)
		if raw.Valid {
			obs.Raw = []byte(raw.String)
		}
		if err := fn(obs); err != nil {
			return err
		}
	}
	return rows.Err()
}

func (s *Store) CountObservations(ctx context.Context) (int64, error) {
	var n int64
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM observations`).Scan(&n)
	return n, err
}

// RecentObservations returns the newest observations first.
func (s *Store) RecentObservations(ctx context.Context, limit int) ([]observation.Observation, error) {
	if limit <= 0 || limit > 5000 {
		limit = 500
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, observed_at, source, collector_id, subject_type, subject, attribute, value, confidence, raw
		FROM observations ORDER BY observed_at DESC, id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("sqlite: recent observations: %w", err)
	}
	defer rows.Close()
	var out []observation.Observation
	for rows.Next() {
		var (
			obs            observation.Observation
			observed       string
			src, styp, att string
			raw            sql.NullString
		)
		if err := rows.Scan(&obs.ID, &observed, &src, &obs.CollectorID, &styp,
			&obs.Subject, &att, &obs.Value, &obs.Confidence, &raw); err != nil {
			return nil, err
		}
		obs.ObservedAt, _ = parseTime(observed)
		obs.Source = observation.Source(src)
		obs.SubjectType = observation.SubjectType(styp)
		obs.Attribute = observation.Attribute(att)
		if raw.Valid {
			obs.Raw = []byte(raw.String)
		}
		out = append(out, obs)
	}
	return out, rows.Err()
}

// ForSubjects returns observations for the given subjects, newest first.
// QueryObservations returns a filtered, paginated page (newest first) and the
// total matching rows.
func (s *Store) QueryObservations(ctx context.Context, f store.ObservationFilter) ([]observation.Observation, int, error) {
	var where []string
	var args []any
	if f.Source != "" {
		where = append(where, "source = ?")
		args = append(args, f.Source)
	}
	if f.Attribute != "" {
		where = append(where, "attribute = ?")
		args = append(args, f.Attribute)
	}
	if q := strings.TrimSpace(f.Query); q != "" {
		where = append(where, "(subject LIKE ? OR value LIKE ?)")
		like := "%" + q + "%"
		args = append(args, like, like)
	}
	clause := ""
	if len(where) > 0 {
		clause = "WHERE " + strings.Join(where, " AND ")
	}

	var total int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(1) FROM observations "+clause, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("sqlite: count observations: %w", err)
	}
	limit := f.Limit
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	offset := f.Offset
	if offset < 0 {
		offset = 0
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, observed_at, source, collector_id, subject_type, subject, attribute, value, confidence, raw
		FROM observations `+clause+` ORDER BY observed_at DESC, id DESC LIMIT ? OFFSET ?`,
		append(append([]any{}, args...), limit, offset)...)
	if err != nil {
		return nil, 0, fmt.Errorf("sqlite: query observations: %w", err)
	}
	defer rows.Close()
	var out []observation.Observation
	for rows.Next() {
		var (
			obs            observation.Observation
			observed       string
			src, styp, att string
			raw            sql.NullString
		)
		if err := rows.Scan(&obs.ID, &observed, &src, &obs.CollectorID, &styp,
			&obs.Subject, &att, &obs.Value, &obs.Confidence, &raw); err != nil {
			return nil, 0, err
		}
		obs.ObservedAt, _ = parseTime(observed)
		obs.Source = observation.Source(src)
		obs.SubjectType = observation.SubjectType(styp)
		obs.Attribute = observation.Attribute(att)
		if raw.Valid {
			obs.Raw = []byte(raw.String)
		}
		out = append(out, obs)
	}
	return out, total, rows.Err()
}

// ObservationFacets returns the distinct sources and attributes present.
func (s *Store) ObservationFacets(ctx context.Context) ([]string, []string, error) {
	distinct := func(col string) ([]string, error) {
		rows, err := s.db.QueryContext(ctx, "SELECT DISTINCT "+col+" FROM observations ORDER BY "+col)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var out []string
		for rows.Next() {
			var v string
			if err := rows.Scan(&v); err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, rows.Err()
	}
	sources, err := distinct("source")
	if err != nil {
		return nil, nil, fmt.Errorf("sqlite: distinct sources: %w", err)
	}
	attrs, err := distinct("attribute")
	if err != nil {
		return nil, nil, fmt.Errorf("sqlite: distinct attributes: %w", err)
	}
	return sources, attrs, nil
}

func (s *Store) ForSubjects(ctx context.Context, subjects []string) ([]observation.Observation, error) {
	if len(subjects) == 0 {
		return nil, nil
	}
	placeholders := make([]string, len(subjects))
	args := make([]any, len(subjects))
	for i, sub := range subjects {
		placeholders[i] = "?"
		args[i] = sub
	}
	q := `SELECT id, observed_at, source, collector_id, subject_type, subject, attribute, value, confidence, raw
		FROM observations WHERE subject IN (` + strings.Join(placeholders, ",") + `)
		ORDER BY observed_at DESC, id DESC`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("sqlite: observations for subjects: %w", err)
	}
	defer rows.Close()

	var out []observation.Observation
	for rows.Next() {
		var (
			obs            observation.Observation
			observed       string
			src, styp, att string
			raw            sql.NullString
		)
		if err := rows.Scan(&obs.ID, &observed, &src, &obs.CollectorID, &styp,
			&obs.Subject, &att, &obs.Value, &obs.Confidence, &raw); err != nil {
			return nil, err
		}
		obs.ObservedAt, _ = parseTime(observed)
		obs.Source = observation.Source(src)
		obs.SubjectType = observation.SubjectType(styp)
		obs.Attribute = observation.Attribute(att)
		if raw.Valid {
			obs.Raw = []byte(raw.String)
		}
		out = append(out, obs)
	}
	return out, rows.Err()
}

// CompactLog removes observations that are neither the first nor the latest in
// their (source, subject, attribute, value) group. Keeping the earliest preserves
// first_seen; keeping the latest preserves last_seen, recency, and the winning
// value — so the reconciled output is unchanged while repeated poller re-emissions
// collapse to two rows.
func (s *Store) CompactLog(ctx context.Context) (int64, error) {
	res, err := s.db.ExecContext(ctx, `
		DELETE FROM observations WHERE id IN (
			SELECT id FROM (
				SELECT id,
					ROW_NUMBER() OVER (PARTITION BY source, subject, attribute, value ORDER BY observed_at ASC, id ASC)  AS rn_first,
					ROW_NUMBER() OVER (PARTITION BY source, subject, attribute, value ORDER BY observed_at DESC, id DESC) AS rn_last
				FROM observations
			)
			WHERE rn_first > 1 AND rn_last > 1
		)`)
	if err != nil {
		return 0, fmt.Errorf("sqlite: compact log: %w", err)
	}
	return res.RowsAffected()
}

// ── EntityStore ──────────────────────────────────────────────────────────────

// ReplaceEntities atomically swaps the entire reconciled entity layer: truncate
// all entity tables, then insert the snapshot, in a single transaction. Readers
// never observe a torn state. This is the persistence half of "rebuildable by
// replaying the log from empty" (§3.3). IDs in the snapshot are honored so the
// reconciler's cross-table references (host_id, subnet_id, ...) hold.
func (s *Store) ReplaceEntities(ctx context.Context, snap entity.Snapshot) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("sqlite: begin replace: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op after a successful Commit

	// Order matters for FK constraints on delete; children first.
	for _, t := range []string{"conflicts", "services", "topology", "addresses", "interfaces", "hosts", "subnets"} {
		if _, err := tx.ExecContext(ctx, "DELETE FROM "+t); err != nil {
			return fmt.Errorf("sqlite: clear %s: %w", t, err)
		}
	}

	for _, sn := range snap.Subnets {
		if _, err := tx.ExecContext(ctx, `INSERT INTO subnets
			(id, cidr, vlan_id, name, source, gateway, first_seen, last_seen)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			sn.ID, sn.CIDR, sn.VLANID, sn.Name, sn.Source, sn.Gateway,
			ft(sn.FirstSeen), ft(sn.LastSeen)); err != nil {
			return fmt.Errorf("sqlite: insert subnet: %w", err)
		}
	}
	for _, h := range snap.Hosts {
		if _, err := tx.ExecContext(ctx, `INSERT INTO hosts
			(id, stable_id, display_name, device_class, os_guess, model, firmware, confidence, is_expected, ignored, tags, icon, notes, first_seen, last_seen)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			h.ID, h.StableID, h.DisplayName, h.DeviceClass, h.OSGuess, h.Model, h.Firmware, h.Confidence,
			b2i(h.IsExpected), b2i(h.Ignored), strings.Join(h.Tags, ","), h.Icon, h.Notes, ft(h.FirstSeen), ft(h.LastSeen)); err != nil {
			return fmt.Errorf("sqlite: insert host: %w", err)
		}
	}
	for _, i := range snap.Interfaces {
		if _, err := tx.ExecContext(ctx, `INSERT INTO interfaces
			(id, host_id, mac, oui_vendor, is_randomized) VALUES (?, ?, ?, ?, ?)`,
			i.ID, i.HostID, i.MAC, i.OUIVendor, b2i(i.IsRandomized)); err != nil {
			return fmt.Errorf("sqlite: insert interface: %w", err)
		}
	}
	for _, a := range snap.Addresses {
		if _, err := tx.ExecContext(ctx, `INSERT INTO addresses
			(id, ip, ip_version, subnet_id, mac, host_id, state, dhcp, first_seen, last_seen)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			a.ID, a.IP, a.IPVersion, a.SubnetID, a.MAC, a.HostID, string(a.State), a.DHCP,
			ft(a.FirstSeen), ft(a.LastSeen)); err != nil {
			return fmt.Errorf("sqlite: insert address: %w", err)
		}
	}
	for _, sv := range snap.Services {
		if _, err := tx.ExecContext(ctx, `INSERT INTO services
			(id, host_id, address_id, proto, port, banner, source, last_seen)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			sv.ID, sv.HostID, sv.AddressID, sv.Proto, sv.Port, sv.Banner, sv.Source,
			ft(sv.LastSeen)); err != nil {
			return fmt.Errorf("sqlite: insert service: %w", err)
		}
	}
	for _, tp := range snap.Topology {
		if _, err := tx.ExecContext(ctx, `INSERT INTO topology
			(id, host_id, switch, switch_port, speed, vlan, source) VALUES (?, ?, ?, ?, ?, ?, ?)`,
			tp.ID, tp.HostID, tp.Switch, tp.SwitchPort, tp.Speed, tp.VLAN, tp.Source); err != nil {
			return fmt.Errorf("sqlite: insert topology: %w", err)
		}
	}
	for _, c := range snap.Conflicts {
		if _, err := tx.ExecContext(ctx, `INSERT INTO conflicts
			(id, subject, attribute, value_a, source_a, count_a, last_seen_a, value_b, source_b, count_b, last_seen_b, opened_at, resolved)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			c.ID, c.Subject, c.Attribute, c.ValueA, c.SourceA, c.CountA, ft(c.LastSeenA),
			c.ValueB, c.SourceB, c.CountB, ft(c.LastSeenB),
			ft(c.OpenedAt), b2i(c.Resolved)); err != nil {
			return fmt.Errorf("sqlite: insert conflict: %w", err)
		}
	}
	return tx.Commit()
}

// LoadEntities reads the full reconciled entity layer (used by the M6 query API
// and the demo). Slices come back in stable id order.
func (s *Store) LoadEntities(ctx context.Context) (entity.Snapshot, error) {
	var snap entity.Snapshot
	var err error
	if snap.Subnets, err = s.loadSubnets(ctx); err != nil {
		return snap, err
	}
	if snap.Hosts, err = s.loadHosts(ctx); err != nil {
		return snap, err
	}
	if snap.Interfaces, err = s.loadInterfaces(ctx); err != nil {
		return snap, err
	}
	if snap.Addresses, err = s.loadAddresses(ctx); err != nil {
		return snap, err
	}
	if snap.Services, err = s.loadServices(ctx); err != nil {
		return snap, err
	}
	if snap.Topology, err = s.loadTopology(ctx); err != nil {
		return snap, err
	}
	if snap.Conflicts, err = s.loadConflicts(ctx); err != nil {
		return snap, err
	}
	return snap, nil
}

func (s *Store) loadSubnets(ctx context.Context) ([]entity.Subnet, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, cidr, vlan_id, name, source, gateway, first_seen, last_seen FROM subnets ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []entity.Subnet
	for rows.Next() {
		var v entity.Subnet
		var vlan sql.NullInt64
		var fs, ls string
		if err := rows.Scan(&v.ID, &v.CIDR, &vlan, &v.Name, &v.Source, &v.Gateway, &fs, &ls); err != nil {
			return nil, err
		}
		v.VLANID = nullIntPtr(vlan)
		v.FirstSeen, _ = parseTime(fs)
		v.LastSeen, _ = parseTime(ls)
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *Store) loadHosts(ctx context.Context) ([]entity.Host, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, stable_id, display_name, device_class, os_guess, model, firmware, confidence, is_expected, ignored, tags, icon, notes, first_seen, last_seen FROM hosts ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []entity.Host
	for rows.Next() {
		var v entity.Host
		var exp, ign int
		var fs, ls, tags string
		if err := rows.Scan(&v.ID, &v.StableID, &v.DisplayName, &v.DeviceClass, &v.OSGuess, &v.Model, &v.Firmware, &v.Confidence, &exp, &ign, &tags, &v.Icon, &v.Notes, &fs, &ls); err != nil {
			return nil, err
		}
		v.IsExpected = exp != 0
		v.Ignored = ign != 0
		if tags != "" {
			v.Tags = strings.Split(tags, ",")
		}
		v.FirstSeen, _ = parseTime(fs)
		v.LastSeen, _ = parseTime(ls)
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *Store) loadInterfaces(ctx context.Context) ([]entity.Interface, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, host_id, mac, oui_vendor, is_randomized FROM interfaces ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []entity.Interface
	for rows.Next() {
		var v entity.Interface
		var rnd int
		if err := rows.Scan(&v.ID, &v.HostID, &v.MAC, &v.OUIVendor, &rnd); err != nil {
			return nil, err
		}
		v.IsRandomized = rnd != 0
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *Store) loadAddresses(ctx context.Context) ([]entity.Address, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, ip, ip_version, subnet_id, mac, host_id, state, dhcp, first_seen, last_seen FROM addresses ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []entity.Address
	for rows.Next() {
		var v entity.Address
		var subnet, host sql.NullInt64
		var st, dhcp, fs, ls string
		if err := rows.Scan(&v.ID, &v.IP, &v.IPVersion, &subnet, &v.MAC, &host, &st, &dhcp, &fs, &ls); err != nil {
			return nil, err
		}
		v.SubnetID = nullInt64Ptr(subnet)
		v.HostID = nullInt64Ptr(host)
		v.State = entity.AddressState(st)
		v.DHCP = dhcp
		v.FirstSeen, _ = parseTime(fs)
		v.LastSeen, _ = parseTime(ls)
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *Store) loadServices(ctx context.Context) ([]entity.Service, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, host_id, address_id, proto, port, banner, source, last_seen FROM services ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []entity.Service
	for rows.Next() {
		var v entity.Service
		var host, addr sql.NullInt64
		var ls string
		if err := rows.Scan(&v.ID, &host, &addr, &v.Proto, &v.Port, &v.Banner, &v.Source, &ls); err != nil {
			return nil, err
		}
		v.HostID = nullInt64Ptr(host)
		v.AddressID = nullInt64Ptr(addr)
		v.LastSeen, _ = parseTime(ls)
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *Store) loadTopology(ctx context.Context) ([]entity.Topology, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, host_id, switch, switch_port, speed, vlan, source FROM topology ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []entity.Topology
	for rows.Next() {
		var v entity.Topology
		var vlan sql.NullInt64
		if err := rows.Scan(&v.ID, &v.HostID, &v.Switch, &v.SwitchPort, &v.Speed, &vlan, &v.Source); err != nil {
			return nil, err
		}
		v.VLAN = nullIntPtr(vlan)
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *Store) loadConflicts(ctx context.Context) ([]entity.Conflict, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, subject, attribute, value_a, source_a, count_a, last_seen_a, value_b, source_b, count_b, last_seen_b, opened_at, resolved FROM conflicts ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []entity.Conflict
	for rows.Next() {
		var v entity.Conflict
		var res int
		var op, lsa, lsb string
		if err := rows.Scan(&v.ID, &v.Subject, &v.Attribute, &v.ValueA, &v.SourceA, &v.CountA, &lsa, &v.ValueB, &v.SourceB, &v.CountB, &lsb, &op, &res); err != nil {
			return nil, err
		}
		v.Resolved = res != 0
		v.OpenedAt, _ = parseTime(op)
		v.LastSeenA, _ = parseTime(lsa)
		v.LastSeenB, _ = parseTime(lsb)
		out = append(out, v)
	}
	return out, rows.Err()
}

// ── conflict resolutions (operator workflow state) ───────────────────────────

func (s *Store) ListResolutions(ctx context.Context) ([]entity.ConflictResolution, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT subject, attribute, chosen_value, chosen_source, note, resolved_at, resolved_by
		FROM conflict_resolutions ORDER BY resolved_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []entity.ConflictResolution
	for rows.Next() {
		var r entity.ConflictResolution
		var at string
		if err := rows.Scan(&r.Subject, &r.Attribute, &r.ChosenValue, &r.ChosenSource, &r.Note, &at, &r.ResolvedBy); err != nil {
			return nil, err
		}
		r.ResolvedAt, _ = parseTime(at)
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) SetResolution(ctx context.Context, r entity.ConflictResolution) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO conflict_resolutions
		(subject, attribute, chosen_value, chosen_source, note, resolved_at, resolved_by)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(subject, attribute) DO UPDATE SET
			chosen_value=excluded.chosen_value, chosen_source=excluded.chosen_source,
			note=excluded.note, resolved_at=excluded.resolved_at, resolved_by=excluded.resolved_by`,
		r.Subject, r.Attribute, r.ChosenValue, r.ChosenSource, r.Note, ft(r.ResolvedAt), r.ResolvedBy)
	return err
}

func (s *Store) DeleteResolution(ctx context.Context, subject, attribute string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM conflict_resolutions WHERE subject=? AND attribute=?`, subject, attribute)
	return err
}

func (s *Store) ListSecuritySuppressions(ctx context.Context) ([]entity.SecuritySuppression, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT stable_id, proto, port, note, suppressed_at, suppressed_by, expires_at
		FROM security_suppressions ORDER BY suppressed_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []entity.SecuritySuppression
	for rows.Next() {
		var sp entity.SecuritySuppression
		var at, exp string
		if err := rows.Scan(&sp.StableID, &sp.Proto, &sp.Port, &sp.Note, &at, &sp.SuppressedBy, &exp); err != nil {
			return nil, err
		}
		sp.SuppressedAt, _ = parseTime(at)
		if exp != "" {
			if t, err := parseTime(exp); err == nil {
				sp.ExpiresAt = &t
			}
		}
		out = append(out, sp)
	}
	return out, rows.Err()
}

func (s *Store) SetSecuritySuppression(ctx context.Context, sp entity.SecuritySuppression) error {
	exp := ""
	if sp.ExpiresAt != nil {
		exp = ft(*sp.ExpiresAt)
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO security_suppressions
		(stable_id, proto, port, note, suppressed_at, suppressed_by, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(stable_id, proto, port) DO UPDATE SET
			note=excluded.note, suppressed_at=excluded.suppressed_at, suppressed_by=excluded.suppressed_by,
			expires_at=excluded.expires_at`,
		sp.StableID, sp.Proto, sp.Port, sp.Note, ft(sp.SuppressedAt), sp.SuppressedBy, exp)
	return err
}

func (s *Store) DeleteSecuritySuppression(ctx context.Context, stableID, proto string, port int) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM security_suppressions WHERE stable_id=? AND proto=? AND port=?`, stableID, proto, port)
	return err
}

// ForgetSubjects deletes the log observations for the given subjects plus the
// host's workflow state (conflict resolutions, security suppressions), in one
// transaction. Returns the number of observations removed.
func (s *Store) ForgetSubjects(ctx context.Context, stableID string, subjects []string) (int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback() //nolint:errcheck // no-op after a successful commit

	var removed int64
	if len(subjects) > 0 {
		placeholders := make([]string, len(subjects))
		args := make([]any, len(subjects))
		for i, sub := range subjects {
			placeholders[i] = "?"
			args[i] = sub
		}
		res, err := tx.ExecContext(ctx, `DELETE FROM observations WHERE subject IN (`+strings.Join(placeholders, ",")+`)`, args...)
		if err != nil {
			return 0, fmt.Errorf("sqlite: forget observations: %w", err)
		}
		removed, _ = res.RowsAffected()
	}
	if stableID != "" {
		if _, err := tx.ExecContext(ctx, `DELETE FROM conflict_resolutions WHERE subject=?`, stableID); err != nil {
			return 0, fmt.Errorf("sqlite: forget resolutions: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM security_suppressions WHERE stable_id=?`, stableID); err != nil {
			return 0, fmt.Errorf("sqlite: forget suppressions: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM availability_events WHERE stable_id=?`, stableID); err != nil {
			return 0, fmt.Errorf("sqlite: forget availability: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM host_merges WHERE secondary=? OR primary_id=?`, stableID, stableID); err != nil {
			return 0, fmt.Errorf("sqlite: forget merges: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return removed, nil
}

// ListMerges returns all host-merge links.
func (s *Store) ListMerges(ctx context.Context) ([]entity.HostMerge, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT secondary, primary_id, created_at, created_by FROM host_merges ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []entity.HostMerge
	for rows.Next() {
		var m entity.HostMerge
		var at string
		if err := rows.Scan(&m.Secondary, &m.Primary, &at, &m.CreatedBy); err != nil {
			return nil, err
		}
		m.CreatedAt, _ = parseTime(at)
		out = append(out, m)
	}
	return out, rows.Err()
}

// SetMerge upserts a merge link.
func (s *Store) SetMerge(ctx context.Context, m entity.HostMerge) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO host_merges (secondary, primary_id, created_at, created_by)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(secondary) DO UPDATE SET primary_id=excluded.primary_id, created_at=excluded.created_at, created_by=excluded.created_by`,
		m.Secondary, m.Primary, ft(m.CreatedAt), m.CreatedBy)
	return err
}

// DeleteMerge removes a merge link (split).
func (s *Store) DeleteMerge(ctx context.Context, secondary string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM host_merges WHERE secondary=?`, secondary)
	return err
}

// ListPrecedence returns all source-precedence rules.
func (s *Store) ListPrecedence(ctx context.Context) ([]entity.SourcePrecedence, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT attribute, source, created_at, created_by FROM source_precedence ORDER BY attribute`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []entity.SourcePrecedence
	for rows.Next() {
		var p entity.SourcePrecedence
		var at string
		if err := rows.Scan(&p.Attribute, &p.Source, &at, &p.CreatedBy); err != nil {
			return nil, err
		}
		p.CreatedAt, _ = parseTime(at)
		out = append(out, p)
	}
	return out, rows.Err()
}

// SetPrecedence upserts a precedence rule.
func (s *Store) SetPrecedence(ctx context.Context, p entity.SourcePrecedence) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO source_precedence (attribute, source, created_at, created_by)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(attribute) DO UPDATE SET source=excluded.source, created_at=excluded.created_at, created_by=excluded.created_by`,
		p.Attribute, p.Source, ft(p.CreatedAt), p.CreatedBy)
	return err
}

// DeletePrecedence clears a precedence rule.
func (s *Store) DeletePrecedence(ctx context.Context, attribute string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM source_precedence WHERE attribute=?`, attribute)
	return err
}

// DeleteObservation removes one observation row by id.
func (s *Store) DeleteObservation(ctx context.Context, id int64) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM observations WHERE id=?`, id)
	if err != nil {
		return 0, fmt.Errorf("sqlite: delete observation: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// DeleteObservations removes observation rows matching the filter (AND-combined).
// Refuses an empty filter so the whole log can't be wiped by accident.
func (s *Store) DeleteObservations(ctx context.Context, f store.ObsDeleteFilter) (int64, error) {
	if f.Empty() {
		return 0, fmt.Errorf("sqlite: refusing empty observation-delete filter")
	}
	var where []string
	var args []any
	if f.Subject != "" {
		where = append(where, "subject=?")
		args = append(args, f.Subject)
	}
	if f.Attribute != "" {
		where = append(where, "attribute=?")
		args = append(args, f.Attribute)
	}
	if f.Value != "" {
		where = append(where, "value=?")
		args = append(args, f.Value)
	}
	if f.ValuePrefix != "" {
		where = append(where, `value LIKE ? ESCAPE '\'`)
		args = append(args, escapeLike(f.ValuePrefix)+"%")
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM observations WHERE `+strings.Join(where, " AND "), args...)
	if err != nil {
		return 0, fmt.Errorf("sqlite: delete observations: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// escapeLike escapes LIKE wildcards so a literal prefix matches literally.
func escapeLike(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "%", "\\%")
	s = strings.ReplaceAll(s, "_", "\\_")
	return s
}

// LatestAvailability returns the most recent online state per host (stable_id).
func (s *Store) LatestAvailability(ctx context.Context) (map[string]bool, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT a.stable_id, a.online FROM availability_events a
		JOIN (SELECT stable_id, MAX(id) AS mid FROM availability_events GROUP BY stable_id) m
		ON a.id = m.mid`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var id string
		var online int
		if err := rows.Scan(&id, &online); err != nil {
			return nil, err
		}
		out[id] = online != 0
	}
	return out, rows.Err()
}

// AppendAvailability records online/offline transition events.
func (s *Store) AppendAvailability(ctx context.Context, events []entity.AvailabilityEvent) error {
	if len(events) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO availability_events (stable_id, online, at) VALUES (?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, e := range events {
		online := 0
		if e.Online {
			online = 1
		}
		if _, err := stmt.ExecContext(ctx, e.StableID, online, ft(e.At)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// AvailabilityForHost returns a host's transition events, oldest first.
func (s *Store) AvailabilityForHost(ctx context.Context, stableID string) ([]entity.AvailabilityEvent, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT online, at FROM availability_events
		WHERE stable_id=? ORDER BY at ASC, id ASC`, stableID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []entity.AvailabilityEvent
	for rows.Next() {
		var online int
		var at string
		if err := rows.Scan(&online, &at); err != nil {
			return nil, err
		}
		t, _ := parseTime(at)
		out = append(out, entity.AvailabilityEvent{StableID: stableID, Online: online != 0, At: t})
	}
	return out, rows.Err()
}

// AllAvailability returns every host's transition events, oldest first.
func (s *Store) AllAvailability(ctx context.Context) ([]entity.AvailabilityEvent, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT stable_id, online, at FROM availability_events ORDER BY at ASC, id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []entity.AvailabilityEvent
	for rows.Next() {
		var e entity.AvailabilityEvent
		var online int
		var at string
		if err := rows.Scan(&e.StableID, &online, &at); err != nil {
			return nil, err
		}
		e.Online = online != 0
		e.At, _ = parseTime(at)
		out = append(out, e)
	}
	return out, rows.Err()
}

// LastSeenBySubject returns the newest non-manual observation time per subject —
// i.e. how recently each device was actually seen on the network (manual
// annotations are excluded so a hand-edited name doesn't keep a gone device alive).
func (s *Store) LastSeenBySubject(ctx context.Context) (map[string]time.Time, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT subject, MAX(observed_at) FROM observations
		WHERE source != ? GROUP BY subject`, string(observation.SourceManual))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]time.Time{}
	for rows.Next() {
		var subject, at string
		if err := rows.Scan(&subject, &at); err != nil {
			return nil, err
		}
		if t, err := parseTime(at); err == nil {
			out[subject] = t
		}
	}
	return out, rows.Err()
}

// ── helpers ──────────────────────────────────────────────────────────────────

func ft(t time.Time) string { return t.UTC().Format(rfc3339ms) }

func parseTime(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	// Tolerate both the ms-precision write format and plain RFC3339.
	for _, layout := range []string{rfc3339ms, time.RFC3339Nano, time.RFC3339, "2006-01-02 15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("sqlite: cannot parse time %q", s)
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

func nullIntPtr(n sql.NullInt64) *int {
	if !n.Valid {
		return nil
	}
	v := int(n.Int64)
	return &v
}

func nullInt64Ptr(n sql.NullInt64) *int64 {
	if !n.Valid {
		return nil
	}
	v := n.Int64
	return &v
}
