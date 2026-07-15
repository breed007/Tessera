-- Named, revocable API tokens for consumers (CableMap, runbook generator,
-- scripts). Only the SHA-256 hash is stored; the plaintext is shown once.
CREATE TABLE IF NOT EXISTS api_tokens (
	id           INTEGER PRIMARY KEY AUTOINCREMENT,
	name         TEXT NOT NULL,
	token_hash   TEXT NOT NULL UNIQUE,
	role         TEXT NOT NULL,
	created_at   TEXT NOT NULL,
	created_by   TEXT NOT NULL DEFAULT '',
	last_used_at TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_api_tokens_hash ON api_tokens (token_hash);
