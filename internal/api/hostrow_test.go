package api

import (
	"testing"
	"time"

	"github.com/breed007/Tessera/internal/entity"
)

// TestPrimaryIPIsMostCurrent pins what the inventory table shows: the address a
// device answers on NOW — active beats stale, and among equals the newest
// last-seen wins — regardless of the order addresses come out of the snapshot.
func TestPrimaryIPIsMostCurrent(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	hid := int64(1)
	snap := entity.Snapshot{
		Hosts: []entity.Host{{ID: 1, StableID: "mac:aa"}},
		Addresses: []entity.Address{
			// Deliberately worst-case order: the oldest, stale address first.
			{IP: "10.0.0.50", HostID: &hid, State: entity.StateStale, LastSeen: t0},
			{IP: "10.0.0.90", HostID: &hid, State: entity.StateStale, LastSeen: t0.Add(48 * time.Hour)},
			{IP: "10.0.0.77", HostID: &hid, State: entity.StateActive, LastSeen: t0.Add(time.Hour)},
		},
	}
	rows := buildHostRows(snap)
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(rows))
	}
	r := rows[0]
	// Active wins even though a stale address was seen more recently.
	if r.PrimaryIP != "10.0.0.77" {
		t.Errorf("primary_ip = %q, want 10.0.0.77 (the active address)", r.PrimaryIP)
	}
	if r.IPs[0] != "10.0.0.77" {
		t.Errorf("ips[0] = %q, want the primary first", r.IPs[0])
	}
	// The rest are history, newest-seen first.
	if r.IPs[1] != "10.0.0.90" || r.IPs[2] != "10.0.0.50" {
		t.Errorf("history order = %v, want [10.0.0.90 10.0.0.50] after the primary", r.IPs[1:])
	}
	if !r.Online {
		t.Error("host with an active address should be online")
	}

	// No active address: the most recently seen one represents the device.
	snap.Addresses = []entity.Address{
		{IP: "10.0.0.50", HostID: &hid, State: entity.StateStale, LastSeen: t0},
		{IP: "10.0.0.90", HostID: &hid, State: entity.StateStale, LastSeen: t0.Add(48 * time.Hour)},
	}
	rows = buildHostRows(snap)
	if rows[0].PrimaryIP != "10.0.0.90" {
		t.Errorf("offline primary_ip = %q, want the newest-seen 10.0.0.90", rows[0].PrimaryIP)
	}
	if rows[0].Online {
		t.Error("host with no active address should be offline")
	}
}

// TestHostRowCarriesSubnetAndVLAN: the inventory can only answer "everything on
// 10.0.20.0/24" (or "on VLAN 20") if each row knows where it lives.
func TestHostRowCarriesSubnetAndVLAN(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	h1, h2 := int64(1), int64(2)
	sid20, sid30 := int64(10), int64(20)
	v20, v30 := 20, 30
	snap := entity.Snapshot{
		Subnets: []entity.Subnet{
			{ID: sid20, CIDR: "10.0.20.0/24", VLANID: &v20, Name: "iot"},
			{ID: sid30, CIDR: "10.0.30.0/24", VLANID: &v30, Name: "guest"},
		},
		Hosts: []entity.Host{{ID: h1, StableID: "mac:aa"}, {ID: h2, StableID: "mac:bb"}},
		Addresses: []entity.Address{
			{IP: "10.0.20.5", HostID: &h1, SubnetID: &sid20, State: entity.StateActive, LastSeen: t0},
			// Multi-homed: same host also holds a guest-VLAN address.
			{IP: "10.0.30.9", HostID: &h1, SubnetID: &sid30, State: entity.StateStale, LastSeen: t0},
			{IP: "10.0.30.7", HostID: &h2, SubnetID: &sid30, State: entity.StateActive, LastSeen: t0},
		},
	}
	byID := map[string]HostRow{}
	for _, r := range buildHostRows(snap) {
		byID[r.StableID] = r
	}
	a := byID["mac:aa"]
	if len(a.Subnets) != 2 || a.Subnets[0] != "10.0.20.0/24" {
		t.Errorf("multi-homed host subnets = %v, want the primary address's subnet first", a.Subnets)
	}
	if len(a.VLANs) != 2 {
		t.Errorf("VLANs = %v, want both", a.VLANs)
	}
	b := byID["mac:bb"]
	if len(b.Subnets) != 1 || b.Subnets[0] != "10.0.30.0/24" || len(b.VLANs) != 1 || b.VLANs[0] != 30 {
		t.Errorf("host b subnets=%v vlans=%v, want [10.0.30.0/24] / [30]", b.Subnets, b.VLANs)
	}
}
