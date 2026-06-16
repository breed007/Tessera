-- §M10: multi-user accounts, runtime settings, sessions, and an audit trail.

CREATE TABLE users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT    NOT NULL,                 -- bcrypt
    role          TEXT    NOT NULL,                 -- admin | viewer
    created_at    TEXT    NOT NULL,
    updated_at    TEXT    NOT NULL
);

-- Runtime settings overlay the file config. Secret values are stored encrypted
-- (is_secret=1) under the master key; plain settings are stored as-is.
CREATE TABLE settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL DEFAULT '',
    is_secret  INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL
);

-- Login sessions (cookie token → user). Pruned on expiry.
CREATE TABLE sessions (
    token      TEXT PRIMARY KEY,
    username   TEXT NOT NULL,
    role       TEXT NOT NULL,
    expires_at TEXT NOT NULL
);
CREATE INDEX idx_sessions_expiry ON sessions (expires_at);

-- Lightweight audit of settings/user changes.
CREATE TABLE audit (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    at       TEXT NOT NULL,
    username TEXT NOT NULL,
    action   TEXT NOT NULL,
    detail   TEXT NOT NULL DEFAULT ''
);
CREATE INDEX idx_audit_at ON audit (at);
