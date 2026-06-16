package store

import (
	"context"
	"database/sql"
	"fmt"
	"io/fs"
	"sort"
	"strings"
)

// RunMigrations applies *.up.sql files from migs in lexical order, tracking
// applied versions in a schema_migrations table. It is intentionally tiny —
// forward-only, no down migrations — which is all Tessera needs and avoids a
// heavyweight migration dependency. Drivers (sqlite, later postgres) call this
// with their own embedded migration FS.
func RunMigrations(ctx context.Context, db *sql.DB, migs fs.FS) error {
	if _, err := db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version TEXT PRIMARY KEY,
			applied_at TEXT NOT NULL DEFAULT (datetime('now'))
		)`); err != nil {
		return fmt.Errorf("store: create schema_migrations: %w", err)
	}

	names, err := fs.Glob(migs, "*.up.sql")
	if err != nil {
		return fmt.Errorf("store: glob migrations: %w", err)
	}
	sort.Strings(names)

	for _, name := range names {
		version := strings.TrimSuffix(name, ".up.sql")

		var exists int
		if err := db.QueryRowContext(ctx,
			`SELECT COUNT(1) FROM schema_migrations WHERE version = ?`, version,
		).Scan(&exists); err != nil {
			return fmt.Errorf("store: check migration %s: %w", version, err)
		}
		if exists > 0 {
			continue
		}

		body, err := fs.ReadFile(migs, name)
		if err != nil {
			return fmt.Errorf("store: read migration %s: %w", name, err)
		}

		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("store: begin migration %s: %w", version, err)
		}
		if _, err := tx.ExecContext(ctx, string(body)); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("store: apply migration %s: %w", version, err)
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO schema_migrations (version) VALUES (?)`, version,
		); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("store: record migration %s: %w", version, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("store: commit migration %s: %w", version, err)
		}
	}
	return nil
}
