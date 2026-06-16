package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/tessera/tessera/internal/account"
)

// This file implements account.Store (§M10): users, sessions, and audit.

func (s *Store) CreateUser(ctx context.Context, u account.User) (int64, error) {
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO users (username, password_hash, role, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?)`,
		u.Username, u.PasswordHash, string(u.Role), ft(u.CreatedAt), ft(u.UpdatedAt))
	if err != nil {
		return 0, fmt.Errorf("sqlite: create user: %w", err)
	}
	return res.LastInsertId()
}

func scanUser(row interface{ Scan(...any) error }) (account.User, error) {
	var u account.User
	var role, created, updated string
	if err := row.Scan(&u.ID, &u.Username, &u.PasswordHash, &role, &created, &updated); err != nil {
		return account.User{}, err
	}
	u.Role = account.Role(role)
	u.CreatedAt, _ = parseTime(created)
	u.UpdatedAt, _ = parseTime(updated)
	return u, nil
}

const userCols = `id, username, password_hash, role, created_at, updated_at`

func (s *Store) UserByName(ctx context.Context, name string) (account.User, bool, error) {
	u, err := scanUser(s.db.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE username = ? COLLATE NOCASE`, name))
	if errors.Is(err, sql.ErrNoRows) {
		return account.User{}, false, nil
	}
	if err != nil {
		return account.User{}, false, err
	}
	return u, true, nil
}

func (s *Store) UserByID(ctx context.Context, id int64) (account.User, bool, error) {
	u, err := scanUser(s.db.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return account.User{}, false, nil
	}
	if err != nil {
		return account.User{}, false, err
	}
	return u, true, nil
}

func (s *Store) ListUsers(ctx context.Context) ([]account.User, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+userCols+` FROM users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []account.User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (s *Store) UpdateUser(ctx context.Context, u account.User) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE users SET username = ?, password_hash = ?, role = ?, updated_at = ? WHERE id = ?`,
		u.Username, u.PasswordHash, string(u.Role), ft(u.UpdatedAt), u.ID)
	return err
}

func (s *Store) DeleteUser(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, id)
	return err
}

func (s *Store) CountUsers(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM users`).Scan(&n)
	return n, err
}

func (s *Store) CountAdmins(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM users WHERE role = 'admin'`).Scan(&n)
	return n, err
}

// ── sessions ─────────────────────────────────────────────────────────────────

func (s *Store) CreateSession(ctx context.Context, token, username string, role account.Role, expires time.Time) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO sessions (token, username, role, expires_at) VALUES (?, ?, ?, ?)`,
		token, username, string(role), ft(expires))
	return err
}

func (s *Store) Session(ctx context.Context, token string) (string, account.Role, bool, error) {
	var username, role, expires string
	err := s.db.QueryRowContext(ctx, `SELECT username, role, expires_at FROM sessions WHERE token = ?`, token).
		Scan(&username, &role, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", false, nil
	}
	if err != nil {
		return "", "", false, err
	}
	exp, _ := parseTime(expires)
	if time.Now().After(exp) {
		_ = s.DeleteSession(ctx, token)
		return "", "", false, nil
	}
	return username, account.Role(role), true, nil
}

func (s *Store) DeleteSession(ctx context.Context, token string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE token = ?`, token)
	return err
}

func (s *Store) PruneSessions(ctx context.Context, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at < ?`, ft(now))
	return err
}

func (s *Store) Audit(ctx context.Context, username, action, detail string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO audit (at, username, action, detail) VALUES (?, ?, ?, ?)`,
		ft(time.Now()), username, action, detail)
	return err
}
