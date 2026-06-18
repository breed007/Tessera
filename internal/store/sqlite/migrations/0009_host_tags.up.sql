-- Operator tags (free-form, multiple), stored comma-joined.
ALTER TABLE hosts ADD COLUMN tags TEXT NOT NULL DEFAULT '';
