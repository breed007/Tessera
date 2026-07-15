// Package account provides multi-user accounts with roles and cookie sessions
// (§M10). Two roles: admin (full control incl. settings + user management) and
// viewer (read-only). Passwords are bcrypt-hashed; sessions are random tokens
// stored server-side.
package account

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// Role is a user's permission level.
type Role string

const (
	RoleAdmin  Role = "admin"
	RoleViewer Role = "viewer"
)

func ValidRole(r Role) bool { return r == RoleAdmin || r == RoleViewer }

// User is an account. PasswordHash is never serialized to the API.
type User struct {
	ID           int64     `json:"id"`
	Username     string    `json:"username"`
	Role         Role      `json:"role"`
	PasswordHash string    `json:"-"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// Store is the persistence the account manager needs.
type Store interface {
	CreateUser(ctx context.Context, u User) (int64, error)
	UserByName(ctx context.Context, name string) (User, bool, error)
	UserByID(ctx context.Context, id int64) (User, bool, error)
	ListUsers(ctx context.Context) ([]User, error)
	UpdateUser(ctx context.Context, u User) error
	DeleteUser(ctx context.Context, id int64) error
	CountUsers(ctx context.Context) (int, error)
	CountAdmins(ctx context.Context) (int, error)

	CreateSession(ctx context.Context, token, username string, role Role, expires time.Time) error
	Session(ctx context.Context, token string) (username string, role Role, ok bool, err error)
	DeleteSession(ctx context.Context, token string) error
	PruneSessions(ctx context.Context, now time.Time) error

	Audit(ctx context.Context, username, action, detail string) error
	ListAudit(ctx context.Context, limit int) ([]AuditEntry, error)

	CreateAPIToken(ctx context.Context, t APIToken) (int64, error)
	ListAPITokens(ctx context.Context) ([]APIToken, error)
	DeleteAPIToken(ctx context.Context, id int64) error
	LookupAPIToken(ctx context.Context, hash string) (APIToken, bool, error)
	TouchAPIToken(ctx context.Context, id int64, at time.Time) error
}

// APIToken is a named, revocable credential for API consumers (CableMap, the
// runbook generator, scripts). Only the SHA-256 hash is stored; the plaintext is
// shown once at creation.
type APIToken struct {
	ID         int64     `json:"id"`
	Name       string    `json:"name"`
	Role       Role      `json:"role"`
	Hash       string    `json:"-"`
	CreatedAt  time.Time `json:"created_at"`
	CreatedBy  string    `json:"created_by,omitempty"`
	LastUsedAt time.Time `json:"last_used_at"`
}

// AuditEntry is one recorded action in the audit trail.
type AuditEntry struct {
	At       time.Time `json:"at"`
	Username string    `json:"username"`
	Action   string    `json:"action"`
	Detail   string    `json:"detail,omitempty"`
}

var (
	ErrInvalidCredentials = errors.New("invalid username or password")
	ErrLastAdmin          = errors.New("cannot remove the last admin")
	ErrUserExists         = errors.New("username already exists")
)

// Manager is the account service.
type Manager struct {
	store      Store
	sessionTTL time.Duration
	now        func() time.Time
}

func NewManager(store Store) *Manager {
	return &Manager{store: store, sessionTTL: 7 * 24 * time.Hour, now: time.Now}
}

// EnsureBootstrapAdmin creates the first admin from the bootstrap credentials
// (set by `tessera setup`) when no users exist yet. No-op once any user exists.
func (m *Manager) EnsureBootstrapAdmin(ctx context.Context, username, passwordHash string) error {
	n, err := m.store.CountUsers(ctx)
	if err != nil || n > 0 {
		return err
	}
	if username == "" || passwordHash == "" {
		return nil // nothing to bootstrap from
	}
	now := m.now().UTC()
	_, err = m.store.CreateUser(ctx, User{
		Username: username, Role: RoleAdmin, PasswordHash: passwordHash,
		CreatedAt: now, UpdatedAt: now,
	})
	return err
}

// CreateFirstAdmin creates the initial admin during first-run setup; it refuses
// once any account exists (so the open setup endpoint can't be abused later).
func (m *Manager) CreateFirstAdmin(ctx context.Context, username, password string) error {
	n, err := m.store.CountUsers(ctx)
	if err != nil {
		return err
	}
	if n > 0 {
		return errors.New("already configured")
	}
	if username == "" {
		return errors.New("username is required")
	}
	if len(password) < 8 {
		return errors.New("password must be at least 8 characters")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	now := m.now().UTC()
	if _, err := m.store.CreateUser(ctx, User{Username: username, Role: RoleAdmin, PasswordHash: string(hash), CreatedAt: now, UpdatedAt: now}); err != nil {
		return err
	}
	_ = m.store.Audit(ctx, username, "setup.first_admin", "")
	return nil
}

// Login verifies credentials and creates a session, returning the cookie token.
func (m *Manager) Login(ctx context.Context, username, password string) (string, User, error) {
	u, ok, err := m.store.UserByName(ctx, username)
	if err != nil {
		return "", User{}, err
	}
	if !ok || bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)) != nil {
		return "", User{}, ErrInvalidCredentials
	}
	token := randomToken()
	if err := m.store.CreateSession(ctx, token, u.Username, u.Role, m.now().Add(m.sessionTTL)); err != nil {
		return "", User{}, err
	}
	return token, u, nil
}

// Session resolves a cookie token to a username + role.
func (m *Manager) Session(ctx context.Context, token string) (string, Role, bool) {
	if token == "" {
		return "", "", false
	}
	user, role, ok, err := m.store.Session(ctx, token)
	if err != nil || !ok {
		return "", "", false
	}
	return user, role, true
}

func (m *Manager) Logout(ctx context.Context, token string) error {
	return m.store.DeleteSession(ctx, token)
}

// CreateUser adds a user (admin action).
func (m *Manager) CreateUser(ctx context.Context, actor, username, password string, role Role) error {
	if !ValidRole(role) {
		return fmt.Errorf("invalid role %q", role)
	}
	if len(password) < 8 {
		return errors.New("password must be at least 8 characters")
	}
	if _, exists, _ := m.store.UserByName(ctx, username); exists {
		return ErrUserExists
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	now := m.now().UTC()
	if _, err := m.store.CreateUser(ctx, User{Username: username, Role: role, PasswordHash: string(hash), CreatedAt: now, UpdatedAt: now}); err != nil {
		return err
	}
	_ = m.store.Audit(ctx, actor, "user.create", username+" ("+string(role)+")")
	return nil
}

func (m *Manager) ListUsers(ctx context.Context) ([]User, error) { return m.store.ListUsers(ctx) }

// UpdateUser changes username/role and, if newPassword is non-empty, the password.
// It refuses to demote or remove the last admin.
func (m *Manager) UpdateUser(ctx context.Context, actor string, id int64, username string, role Role, newPassword string) error {
	u, ok, err := m.store.UserByID(ctx, id)
	if err != nil || !ok {
		return errors.New("user not found")
	}
	if u.Role == RoleAdmin && role != RoleAdmin {
		if err := m.guardLastAdmin(ctx); err != nil {
			return err
		}
	}
	if !ValidRole(role) {
		return fmt.Errorf("invalid role %q", role)
	}
	u.Username, u.Role, u.UpdatedAt = username, role, m.now().UTC()
	if newPassword != "" {
		if len(newPassword) < 8 {
			return errors.New("password must be at least 8 characters")
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
		if err != nil {
			return err
		}
		u.PasswordHash = string(hash)
	}
	if err := m.store.UpdateUser(ctx, u); err != nil {
		return err
	}
	_ = m.store.Audit(ctx, actor, "user.update", username)
	return nil
}

func (m *Manager) DeleteUser(ctx context.Context, actor string, id int64) error {
	u, ok, err := m.store.UserByID(ctx, id)
	if err != nil || !ok {
		return errors.New("user not found")
	}
	if u.Role == RoleAdmin {
		if err := m.guardLastAdmin(ctx); err != nil {
			return err
		}
	}
	if err := m.store.DeleteUser(ctx, id); err != nil {
		return err
	}
	_ = m.store.Audit(ctx, actor, "user.delete", u.Username)
	return nil
}

// ChangePassword updates the calling user's own password.
func (m *Manager) ChangePassword(ctx context.Context, username, current, next string) error {
	u, ok, err := m.store.UserByName(ctx, username)
	if err != nil || !ok {
		return errors.New("user not found")
	}
	if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(current)) != nil {
		return ErrInvalidCredentials
	}
	if len(next) < 8 {
		return errors.New("password must be at least 8 characters")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(next), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	u.PasswordHash, u.UpdatedAt = string(hash), m.now().UTC()
	if err := m.store.UpdateUser(ctx, u); err != nil {
		return err
	}
	_ = m.store.Audit(ctx, username, "user.password", "self")
	return nil
}

// Audit records an action in the audit trail.
func (m *Manager) Audit(ctx context.Context, username, action, detail string) error {
	return m.store.Audit(ctx, username, action, detail)
}

// CreateAPIToken generates a new token, stores its hash, and returns the
// plaintext ONCE (never recoverable afterward). Format: "tsk_" + 32 random bytes.
func (m *Manager) CreateAPIToken(ctx context.Context, name string, role Role, createdBy string) (plaintext string, t APIToken, err error) {
	if !ValidRole(role) {
		return "", APIToken{}, fmt.Errorf("invalid role")
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", APIToken{}, err
	}
	plaintext = "tsk_" + hex.EncodeToString(buf)
	t = APIToken{Name: name, Role: role, Hash: hashToken(plaintext), CreatedAt: m.now().UTC(), CreatedBy: createdBy}
	id, err := m.store.CreateAPIToken(ctx, t)
	if err != nil {
		return "", APIToken{}, err
	}
	t.ID = id
	_ = m.store.Audit(ctx, createdBy, "token.create", name+" ("+string(role)+")")
	return plaintext, t, nil
}

// ListAPITokens returns the tokens (metadata only, no hashes/plaintext).
func (m *Manager) ListAPITokens(ctx context.Context) ([]APIToken, error) {
	return m.store.ListAPITokens(ctx)
}

// DeleteAPIToken revokes a token.
func (m *Manager) DeleteAPIToken(ctx context.Context, actor string, id int64) error {
	if err := m.store.DeleteAPIToken(ctx, id); err != nil {
		return err
	}
	_ = m.store.Audit(ctx, actor, "token.delete", fmt.Sprintf("id=%d", id))
	return nil
}

// VerifyAPIToken resolves a presented token to its name + role, or ok=false. It
// updates last-used at most once a minute to avoid a write per request.
func (m *Manager) VerifyAPIToken(ctx context.Context, presented string) (name string, role Role, ok bool) {
	if !strings.HasPrefix(presented, "tsk_") {
		return "", "", false
	}
	t, found, err := m.store.LookupAPIToken(ctx, hashToken(presented))
	if err != nil || !found {
		return "", "", false
	}
	if m.now().Sub(t.LastUsedAt) > time.Minute {
		_ = m.store.TouchAPIToken(ctx, t.ID, m.now().UTC())
	}
	return t.Name, t.Role, true
}

func hashToken(t string) string {
	sum := sha256.Sum256([]byte(t))
	return hex.EncodeToString(sum[:])
}

// ListAudit returns the most recent audit entries (newest first).
func (m *Manager) ListAudit(ctx context.Context, limit int) ([]AuditEntry, error) {
	return m.store.ListAudit(ctx, limit)
}

func (m *Manager) guardLastAdmin(ctx context.Context) error {
	n, err := m.store.CountAdmins(ctx)
	if err != nil {
		return err
	}
	if n <= 1 {
		return ErrLastAdmin
	}
	return nil
}

func randomToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
