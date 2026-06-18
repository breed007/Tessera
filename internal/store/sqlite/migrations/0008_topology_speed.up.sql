-- Negotiated link speed (Mbps) for a topology edge — populated for gear uplinks.
ALTER TABLE topology ADD COLUMN speed TEXT NOT NULL DEFAULT '';
