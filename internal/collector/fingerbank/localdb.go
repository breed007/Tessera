package fingerbank

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	_ "modernc.org/sqlite"
)

// localDBEnricher classifies entirely offline against a local SQLite database —
// the fully-offline alternative to the API (§7), with ZERO external calls. It
// expects a table:
//
//	combinations(dhcp_fingerprint TEXT, device_name TEXT, score INTEGER)
//
// keyed (or indexed) on dhcp_fingerprint. A converter from the official daily
// Fingerbank dump populates this; the lookup contract is identical to api mode
// so the rest of the system doesn't care which is in use.
type localDBEnricher struct {
	db *sql.DB
}

// NewLocalDB opens the local Fingerbank database at path (read-only).
func NewLocalDB(path string) (Enricher, error) {
	if path == "" {
		return nil, errors.New("fingerbank: local_db mode requires fingerbank.db_path")
	}
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		return nil, fmt.Errorf("fingerbank: open local db: %w", err)
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("fingerbank: local db unreadable: %w", err)
	}
	return &localDBEnricher{db: db}, nil
}

func (e *localDBEnricher) Mode() string { return "local_db" }
func (e *localDBEnricher) Close() error { return e.db.Close() }

// Classify looks up the exact DHCP fingerprint. A miss is a valid not-found
// answer (no network is ever touched).
func (e *localDBEnricher) Classify(ctx context.Context, sig Signature) (Verdict, error) {
	if sig.DHCPFingerprint == "" {
		return Verdict{Found: false}, nil
	}
	var name string
	var score int
	err := e.db.QueryRowContext(ctx,
		`SELECT device_name, score FROM combinations WHERE dhcp_fingerprint = ? LIMIT 1`,
		sig.DHCPFingerprint,
	).Scan(&name, &score)
	if errors.Is(err, sql.ErrNoRows) {
		return Verdict{Found: false}, nil
	}
	if err != nil {
		return Verdict{}, fmt.Errorf("fingerbank: local lookup: %w", err)
	}
	return Verdict{Found: true, DeviceClass: name, Score: clampScore(score)}, nil
}
