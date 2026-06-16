-- Firmware/version string for a host (UniFi gear reports it via the controller).
ALTER TABLE hosts ADD COLUMN firmware TEXT NOT NULL DEFAULT '';
