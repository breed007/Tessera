-- Source-precedence policy: for an attribute, always prefer this source's value
-- during reconciliation (resolves a class of conflicts at once). Workflow state.
CREATE TABLE IF NOT EXISTS source_precedence (
	attribute  TEXT NOT NULL PRIMARY KEY,
	source     TEXT NOT NULL,
	created_at TEXT NOT NULL,
	created_by TEXT NOT NULL DEFAULT ''
);
