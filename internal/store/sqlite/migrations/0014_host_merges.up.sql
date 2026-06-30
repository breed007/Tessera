-- Operator "these two hosts are the same device" links. The reconciler folds the
-- secondary stable_id into the primary by canonicalizing host keys. Workflow
-- state, kept separately from the derived entity layer. Split = delete the row.
CREATE TABLE IF NOT EXISTS host_merges (
	secondary  TEXT NOT NULL PRIMARY KEY,
	primary_id TEXT NOT NULL,
	created_at TEXT NOT NULL,
	created_by TEXT NOT NULL DEFAULT ''
);
