-- §M12: operator-chosen device icon id (empty → auto-assigned).
ALTER TABLE hosts ADD COLUMN icon TEXT NOT NULL DEFAULT '';
