-- Provenance for a derived conflict: how many observations support each side and
-- when each was last seen. Conflicts are rebuilt every reconcile, so these are
-- just additional persisted columns of the derived row.
ALTER TABLE conflicts ADD COLUMN count_a INTEGER NOT NULL DEFAULT 0;
ALTER TABLE conflicts ADD COLUMN last_seen_a TEXT NOT NULL DEFAULT '';
ALTER TABLE conflicts ADD COLUMN count_b INTEGER NOT NULL DEFAULT 0;
ALTER TABLE conflicts ADD COLUMN last_seen_b TEXT NOT NULL DEFAULT '';
