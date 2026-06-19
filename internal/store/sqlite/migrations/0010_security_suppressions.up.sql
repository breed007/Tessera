-- Operator acknowledgements of security findings: suppress (accept-risk) a
-- specific exposed service or host-level finding, with a note. Workflow state,
-- persisted independently of the derived findings list. A zero port (proto '')
-- suppresses a host-level finding such as "large attack surface".
CREATE TABLE IF NOT EXISTS security_suppressions (
	stable_id     TEXT NOT NULL,
	proto         TEXT NOT NULL DEFAULT '',
	port          INTEGER NOT NULL DEFAULT 0,
	note          TEXT NOT NULL DEFAULT '',
	suppressed_at TEXT NOT NULL,
	suppressed_by TEXT NOT NULL DEFAULT '',
	PRIMARY KEY (stable_id, proto, port)
);
