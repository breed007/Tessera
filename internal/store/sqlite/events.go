package sqlite

import (
	"context"
	"strings"

	"github.com/breed007/Tessera/internal/entity"
)

// AppendEvents inserts change events (append-only) in one transaction.
func (s *Store) AppendEvents(ctx context.Context, evs []entity.Event) error {
	if len(evs) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	stmt, err := tx.PrepareContext(ctx,
		`INSERT INTO events (at, kind, stable_id, message, old_value, new_value) VALUES (?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, e := range evs {
		if _, err := stmt.ExecContext(ctx, ft(e.At), e.Kind, e.StableID, e.Message, e.Old, e.New); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ListEvents returns change events per the filter. With SinceID > 0 it returns
// events with a higher id in ASCENDING id order (incremental sync); otherwise it
// returns the newest first. Kinds, when non-empty, restricts to those kinds.
func (s *Store) ListEvents(ctx context.Context, f entity.EventFilter) ([]entity.Event, error) {
	limit := f.Limit
	if limit <= 0 || limit > 2000 {
		limit = 200
	}
	var (
		where []string
		args  []any
	)
	if f.SinceID > 0 {
		where = append(where, "id > ?")
		args = append(args, f.SinceID)
	}
	if len(f.Kinds) > 0 {
		ph := make([]string, len(f.Kinds))
		for i, k := range f.Kinds {
			ph[i] = "?"
			args = append(args, k)
		}
		where = append(where, "kind IN ("+strings.Join(ph, ",")+")")
	}
	q := `SELECT id, at, kind, stable_id, message, old_value, new_value FROM events`
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	// Ascending for cursor sync (stable forward progress); newest-first otherwise.
	if f.SinceID > 0 {
		q += " ORDER BY id ASC"
	} else {
		q += " ORDER BY id DESC"
	}
	q += " LIMIT ?"
	args = append(args, limit)

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []entity.Event
	for rows.Next() {
		var e entity.Event
		var at string
		if err := rows.Scan(&e.ID, &at, &e.Kind, &e.StableID, &e.Message, &e.Old, &e.New); err != nil {
			return nil, err
		}
		e.At, _ = parseTime(at)
		out = append(out, e)
	}
	return out, rows.Err()
}

// CountEvents returns the number of rows in the change history.
func (s *Store) CountEvents(ctx context.Context) (int64, error) {
	var n int64
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM events`).Scan(&n)
	return n, err
}

// PruneEvents keeps exactly the most recent `keep` events (by id) and deletes
// the rest — a hard bound on the table for a long-running instance.
func (s *Store) PruneEvents(ctx context.Context, keep int) (int64, error) {
	if keep <= 0 {
		return 0, nil
	}
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM events WHERE id NOT IN (SELECT id FROM events ORDER BY id DESC LIMIT ?)`, keep)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}
