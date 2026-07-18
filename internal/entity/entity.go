// Package entity holds the reconciled "current best view" types (§3.2). These
// are fully rebuildable from the observation log by the reconciler — they are
// derived state, never a source of truth. Human (manual) annotations are the
// one exception: they are authoritative and survive reconciliation (§3.2).
package entity

import "time"

// AddressState is the lifecycle of an IP binding (§3.2), aged by the reconciler
// (§3.3): active → stale → free as supporting observations age out; reserved is
// a human annotation.
type AddressState string

const (
	StateActive   AddressState = "active"
	StateStale    AddressState = "stale"
	StateFree     AddressState = "free"
	StateReserved AddressState = "reserved"
)

// Subnet is a slice of the address space (§3.2). Seeded by UniFi or inferred
// from traffic, or added manually.
type Subnet struct {
	ID        int64     `json:"id"`
	CIDR      string    `json:"cidr"`
	VLANID    *int      `json:"vlan_id,omitempty"`
	Name      string    `json:"name,omitempty"`
	Source    string    `json:"source"`
	Gateway   string    `json:"gateway,omitempty"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// Host is a physical/logical device (§3.2). StableID is the reconciler's
// identity key (e.g. "mac:aa:bb:.." or provisional "ip:10.0.0.5").
type Host struct {
	ID          int64     `json:"id"`
	StableID    string    `json:"stable_id"`
	DisplayName string    `json:"display_name,omitempty"`
	DeviceClass string    `json:"device_class,omitempty"`
	OSGuess     string    `json:"os_guess,omitempty"`
	Model       string    `json:"model,omitempty"`    // precise hardware model (mDNS self-report > UniFi)
	Firmware    string    `json:"firmware,omitempty"` // device firmware/version (UniFi gear via the controller)
	Confidence  int       `json:"confidence"`
	IsExpected  bool      `json:"is_expected"`
	Ignored     bool      `json:"ignored"`        // operator suppressed this device from review
	Tags        []string  `json:"tags,omitempty"` // operator tags (free-form, multiple)
	Icon        string    `json:"icon,omitempty"` // operator-chosen icon id; empty → auto (§M12)
	Notes       string    `json:"notes,omitempty"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
}

// Interface is one MAC owned by a host (§3.2). A host can own several. Randomized
// (locally-administered) MACs are flagged so identity claims resting on them are
// down-weighted (§6).
type Interface struct {
	ID           int64  `json:"id"`
	HostID       int64  `json:"host_id"`
	MAC          string `json:"mac"`
	OUIVendor    string `json:"oui_vendor,omitempty"`
	IsRandomized bool   `json:"is_randomized"`
}

// Address is an IP and its current binding (§3.2).
type Address struct {
	ID        int64        `json:"id"`
	IP        string       `json:"ip"`
	IPVersion int          `json:"ip_version"`
	SubnetID  *int64       `json:"subnet_id,omitempty"`
	MAC       string       `json:"mac,omitempty"`
	HostID    *int64       `json:"host_id,omitempty"`
	State     AddressState `json:"state"`
	DHCP      string       `json:"dhcp,omitempty"` // "reserved" (static mapping) | "dynamic", from the DHCP server
	FirstSeen time.Time    `json:"first_seen"`
	LastSeen  time.Time    `json:"last_seen"`
}

// Service is an observed listening service on a host/address (§3.2).
type Service struct {
	ID        int64     `json:"id"`
	HostID    *int64    `json:"host_id,omitempty"`
	AddressID *int64    `json:"address_id,omitempty"`
	Proto     string    `json:"proto"`
	Port      int       `json:"port"`
	Banner    string    `json:"banner,omitempty"`
	Source    string    `json:"source"`
	LastSeen  time.Time `json:"last_seen"`
}

// Topology is a host's physical placement from UniFi port↔MAC (§3.2).
type Topology struct {
	ID         int64  `json:"id"`
	HostID     int64  `json:"host_id"`
	Switch     string `json:"switch"`
	SwitchPort string `json:"switch_port"`
	Speed      string `json:"speed,omitempty"` // negotiated link speed in Mbps (uplinks)
	VLAN       *int   `json:"vlan,omitempty"`
	Source     string `json:"source"`
}

// Conflict records a disagreement between two sources on a high-value attribute
// (§3.3). Conflicts are surfaced, not silently resolved; the higher-confidence
// value stays current.
type Conflict struct {
	ID        int64     `json:"id"`
	Subject   string    `json:"subject"`
	Attribute string    `json:"attribute"`
	ValueA    string    `json:"value_a"`
	SourceA   string    `json:"source_a"`
	CountA    int       `json:"count_a"`     // supporting observations for value A
	LastSeenA time.Time `json:"last_seen_a"` // most recent observation of value A
	ValueB    string    `json:"value_b"`
	SourceB   string    `json:"source_b"`
	CountB    int       `json:"count_b"`
	LastSeenB time.Time `json:"last_seen_b"`
	OpenedAt  time.Time `json:"opened_at"`
	Resolved  bool      `json:"resolved"`
}

// ConflictResolution is an operator's decision on a conflict: which value is the
// source of truth for a (subject, attribute), plus an optional note. It is
// workflow state (not a network observation) and persists independently of the
// derived conflict list — the chosen value is ALSO written as a manual
// annotation so it actually wins reconciliation.
type ConflictResolution struct {
	Subject      string    `json:"subject"`
	Attribute    string    `json:"attribute"`
	ChosenValue  string    `json:"chosen_value"`
	ChosenSource string    `json:"chosen_source"`
	Note         string    `json:"note,omitempty"`
	ResolvedAt   time.Time `json:"resolved_at"`
	ResolvedBy   string    `json:"resolved_by,omitempty"`
}

// SecuritySuppression is an operator's decision to acknowledge/accept a security
// finding so it stops counting as active (and stops firing alerts), with an
// optional note explaining why. Keyed by host + service; a zero port (proto "")
// suppresses a host-level finding such as "large attack surface". Workflow state,
// independent of the derived findings list.
type SecuritySuppression struct {
	StableID     string     `json:"stable_id"`
	Proto        string     `json:"proto,omitempty"`
	Port         int        `json:"port,omitempty"`
	Note         string     `json:"note,omitempty"`
	SuppressedAt time.Time  `json:"suppressed_at"`
	SuppressedBy string     `json:"suppressed_by,omitempty"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"` // nil = indefinite
}

// Active reports whether the suppression is still in effect at the given time
// (indefinite suppressions are always active).
func (s SecuritySuppression) Active(now time.Time) bool {
	return s.ExpiresAt == nil || now.Before(*s.ExpiresAt)
}

// SourcePrecedence is an operator policy: for the named attribute, always prefer
// this source's value (the reconciler picks it in the fold; manual still wins).
// Resolves a whole class of conflicts at once.
type SourcePrecedence struct {
	Attribute string    `json:"attribute"`
	Source    string    `json:"source"`
	CreatedAt time.Time `json:"created_at"`
	CreatedBy string    `json:"created_by,omitempty"`
}

// HostMerge is an operator decision that two host identities are the same device:
// the Secondary stable_id folds into the Primary during reconciliation (the
// reconciler canonicalizes host keys through these links — append-safe, no log
// rewrite). Split = delete the link.
type HostMerge struct {
	Secondary string    `json:"secondary"`
	Primary   string    `json:"primary"`
	CreatedAt time.Time `json:"created_at"`
	CreatedBy string    `json:"created_by,omitempty"`
}

// AvailabilityEvent records an online/offline transition for a host (online =
// has at least one active address). Appended only when the state flips, so the
// table is bounded by transitions, not time.
type AvailabilityEvent struct {
	StableID string    `json:"stable_id,omitempty"`
	Online   bool      `json:"online"`
	At       time.Time `json:"at"`
}

// Event is one persisted change in the network — the append-only "what changed"
// history that powers the Activity feed and lets API consumers sync
// incrementally by cursor. Written by the reconcile-delta detector (transition-
// based, so it doesn't flap), independent of whether webhook alerting is on.
type Event struct {
	ID       int64     `json:"id"`
	At       time.Time `json:"at"`
	Kind     string    `json:"kind"`     // new_device|device_offline|device_online|ip_changed|conflict|risky_service
	StableID string    `json:"stable_id"` // the host (or conflict subject) the change is about
	Message  string    `json:"message"`  // human-readable summary
	Old      string    `json:"old,omitempty"`
	New      string    `json:"new,omitempty"`
}

// EventFilter selects events for ListEvents. SinceID returns only events with a
// higher id (the incremental-sync cursor); Kinds, when non-empty, restricts to
// those kinds; Limit caps the result (newest first when SinceID is zero).
type EventFilter struct {
	SinceID int64
	Kinds   []string
	Limit   int
}

// Snapshot is the full reconciled entity layer at a point in time. The
// reconciler rebuilds it from the log and the store persists it atomically
// (Reset + insert), which is exactly the §3.3 "reconstructable by replaying the
// observation log from empty" acceptance test.
type Snapshot struct {
	Subnets    []Subnet    `json:"subnets"`
	Hosts      []Host      `json:"hosts"`
	Interfaces []Interface `json:"interfaces"`
	Addresses  []Address   `json:"addresses"`
	Services   []Service   `json:"services"`
	Topology   []Topology  `json:"topology"`
	Conflicts  []Conflict  `json:"conflicts"`
}

// SubjectsForHost returns the observation-log subjects that make up a host — its
// interface MAC(s) and bound IP(s). These are the keys to delete when forgetting
// a device (so it can be rediscovered fresh).
func (s Snapshot) SubjectsForHost(hostID int64) []string {
	seen := map[string]bool{}
	var out []string
	add := func(v string) {
		if v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	for _, i := range s.Interfaces {
		if i.HostID == hostID {
			add(i.MAC)
		}
	}
	for _, a := range s.Addresses {
		if a.HostID != nil && *a.HostID == hostID {
			add(a.IP)
		}
	}
	return out
}
