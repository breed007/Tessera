-- Device availability history: one row per online/offline transition (online =
-- the host has at least one active address). Bounded by transitions, not time.
CREATE TABLE IF NOT EXISTS availability_events (
	id        INTEGER PRIMARY KEY AUTOINCREMENT,
	stable_id TEXT    NOT NULL,
	online    INTEGER NOT NULL,
	at        TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_avail_host ON availability_events (stable_id, at);
