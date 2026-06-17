-- Precise hardware model string (mDNS self-report, falling back to UniFi).
ALTER TABLE hosts ADD COLUMN model TEXT NOT NULL DEFAULT '';
