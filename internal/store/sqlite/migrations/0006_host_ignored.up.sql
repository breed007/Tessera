-- Operator review status: a device suppressed from the review queue (ignored).
ALTER TABLE hosts ADD COLUMN ignored INTEGER NOT NULL DEFAULT 0;
