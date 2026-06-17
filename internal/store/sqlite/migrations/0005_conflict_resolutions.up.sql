-- Operator decisions on conflicts: which value is source of truth, plus a note.
-- Workflow state, persisted independently of the derived conflict list.
CREATE TABLE IF NOT EXISTS conflict_resolutions (
	subject       TEXT NOT NULL,
	attribute     TEXT NOT NULL,
	chosen_value  TEXT NOT NULL DEFAULT '',
	chosen_source TEXT NOT NULL DEFAULT '',
	note          TEXT NOT NULL DEFAULT '',
	resolved_at   TEXT NOT NULL,
	resolved_by   TEXT NOT NULL DEFAULT '',
	PRIMARY KEY (subject, attribute)
);
