-- Tessera initial schema (§3). Two layers:
--   1. the append-only observation log (raw, never mutated)
--   2. the reconciled entity tables (derived, fully rebuildable from the log)
-- Timestamps are stored as RFC3339 TEXT (UTC). Booleans are INTEGER 0/1.

-- ─────────────────────────────────────────────────────────────────────────────
-- §3.1 Observation log — append-only. Nothing updates or deletes these rows.
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE observations (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    observed_at  TEXT    NOT NULL,            -- when the signal was seen
    written_at   TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')), -- when appended (audit)
    source       TEXT    NOT NULL,            -- source enum (passive_arp, unifi, ...)
    collector_id TEXT    NOT NULL,            -- which sensor/poller instance produced it
    subject_type TEXT    NOT NULL,            -- mac | ipv4 | ipv6 | host
    subject      TEXT    NOT NULL,            -- normalized identifier
    attribute    TEXT    NOT NULL,            -- what is asserted (ip_binding, os_guess, ...)
    value        TEXT    NOT NULL,            -- asserted value (text or JSON)
    confidence   INTEGER NOT NULL,            -- 0–100
    raw          TEXT                          -- optional original payload (JSON), nullable
);

-- Replay order is (observed_at, id); the reconciler folds in this order.
CREATE INDEX idx_obs_replay  ON observations (observed_at, id);
-- Reconciler looks up the supporting observations for a given fact.
CREATE INDEX idx_obs_subject ON observations (subject, attribute);

-- ─────────────────────────────────────────────────────────────────────────────
-- §3.2 Reconciled entities — derived state, rebuilt by replaying the log.
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE subnets (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    cidr       TEXT    NOT NULL,
    vlan_id    INTEGER,
    name       TEXT    NOT NULL DEFAULT '',
    source     TEXT    NOT NULL,
    gateway    TEXT    NOT NULL DEFAULT '',
    first_seen TEXT    NOT NULL,
    last_seen  TEXT    NOT NULL,
    UNIQUE (cidr, vlan_id)
);

CREATE TABLE hosts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    stable_id    TEXT    NOT NULL UNIQUE,     -- reconciler identity key (mac:.. / ip:..)
    display_name TEXT    NOT NULL DEFAULT '',
    device_class TEXT    NOT NULL DEFAULT '',
    os_guess     TEXT    NOT NULL DEFAULT '',
    confidence   INTEGER NOT NULL DEFAULT 0,
    is_expected  INTEGER NOT NULL DEFAULT 0,  -- human annotation
    notes        TEXT    NOT NULL DEFAULT '',
    first_seen   TEXT    NOT NULL,
    last_seen    TEXT    NOT NULL
);

CREATE TABLE interfaces (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id       INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    mac           TEXT    NOT NULL UNIQUE,
    oui_vendor    TEXT    NOT NULL DEFAULT '',
    is_randomized INTEGER NOT NULL DEFAULT 0  -- locally-administered bit set (§6)
);
CREATE INDEX idx_iface_host ON interfaces (host_id);

CREATE TABLE addresses (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ip         TEXT    NOT NULL,
    ip_version INTEGER NOT NULL,              -- 4 | 6
    subnet_id  INTEGER REFERENCES subnets(id) ON DELETE SET NULL,
    mac        TEXT    NOT NULL DEFAULT '',
    host_id    INTEGER REFERENCES hosts(id) ON DELETE SET NULL,
    state      TEXT    NOT NULL,              -- active | stale | free | reserved
    first_seen TEXT    NOT NULL,
    last_seen  TEXT    NOT NULL,
    UNIQUE (ip, ip_version)
);
CREATE INDEX idx_addr_host ON addresses (host_id);
CREATE INDEX idx_addr_mac  ON addresses (mac);

CREATE TABLE services (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id    INTEGER REFERENCES hosts(id) ON DELETE CASCADE,
    address_id INTEGER REFERENCES addresses(id) ON DELETE CASCADE,
    proto      TEXT    NOT NULL,
    port       INTEGER NOT NULL,
    banner     TEXT    NOT NULL DEFAULT '',
    source     TEXT    NOT NULL,
    last_seen  TEXT    NOT NULL
);
CREATE INDEX idx_svc_host ON services (host_id);

CREATE TABLE topology (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id     INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    switch      TEXT    NOT NULL,
    switch_port TEXT    NOT NULL,
    vlan        INTEGER,
    source      TEXT    NOT NULL
);
CREATE INDEX idx_topo_host ON topology (host_id);

CREATE TABLE conflicts (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    subject   TEXT    NOT NULL,
    attribute TEXT    NOT NULL,
    value_a   TEXT    NOT NULL,
    source_a  TEXT    NOT NULL,
    value_b   TEXT    NOT NULL,
    source_b  TEXT    NOT NULL,
    opened_at TEXT    NOT NULL,
    resolved  INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_conflict_subject ON conflicts (subject, attribute);
