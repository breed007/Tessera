-- DHCP lease class for an address, ingested from the DHCP server (UniFi, dnsmasq,
-- …): 'reserved' (static mapping) or 'dynamic'. Empty = unknown / no DHCP source.
ALTER TABLE addresses ADD COLUMN dhcp TEXT NOT NULL DEFAULT '';
