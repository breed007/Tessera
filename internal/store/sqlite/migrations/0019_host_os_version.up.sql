-- OS release, separate from os_guess so each is contested on its own evidence.
-- Bare ("26.6", "13", "11 24H2 (build 26100)"); the UI composes the two.
ALTER TABLE hosts ADD COLUMN os_version TEXT NOT NULL DEFAULT '';
