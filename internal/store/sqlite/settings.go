package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Implements settings.Store (§M10): a small key/value table.

func (s *Store) SettingGet(ctx context.Context, key string) (string, bool, error) {
	var v string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return v, true, nil
}

func (s *Store) SettingSet(ctx context.Context, key, value string, isSecret bool) error {
	sec := 0
	if isSecret {
		sec = 1
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO settings (key, value, is_secret, updated_at) VALUES (?, ?, ?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value, is_secret = excluded.is_secret, updated_at = excluded.updated_at`,
		key, value, sec, ft(time.Now()))
	return err
}
