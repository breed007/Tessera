-- Append-only change history (the "what changed on my network" feed + the
-- incremental-sync cursor for API consumers). One row per detected transition;
-- transitions are rare, so this table grows slowly.
CREATE TABLE IF NOT EXISTS events (
	id        INTEGER PRIMARY KEY AUTOINCREMENT,
	at        TEXT NOT NULL,
	kind      TEXT NOT NULL,
	stable_id TEXT NOT NULL DEFAULT '',
	message   TEXT NOT NULL DEFAULT '',
	old_value TEXT NOT NULL DEFAULT '',
	new_value TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_events_kind ON events (kind);
CREATE INDEX IF NOT EXISTS idx_events_stable ON events (stable_id);
