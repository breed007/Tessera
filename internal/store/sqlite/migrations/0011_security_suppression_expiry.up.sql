-- Optional expiry for a security suppression. Empty string = indefinite;
-- otherwise an RFC3339 timestamp after which the suppression no longer applies.
ALTER TABLE security_suppressions ADD COLUMN expires_at TEXT NOT NULL DEFAULT '';
