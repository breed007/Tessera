package reconcile

import (
	"context"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/tessera/tessera/internal/entity"
	"github.com/tessera/tessera/internal/observation"
	"github.com/tessera/tessera/internal/store"
	"github.com/tessera/tessera/internal/store/sqlite"
)

func newStore(t *testing.T) store.Store {
	t.Helper()
	dsn := filepath.Join(t.TempDir(), "test.db")
	st, err := sqlite.Open(dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return st
}

func TestDHCPLeaseFold(t *testing.T) {
	st := newStore(t)
	ctx := context.Background()
	sink := observation.NewSink("seed", st)
	rec := func(src observation.Source, sty observation.SubjectType, subj string, a observation.Attribute, v string, c int) {
		if _, err := sink.Record(ctx, src, sty, subj, a, v, c, observation.At(testT0)); err != nil {
			t.Fatal(err)
		}
	}
	rec(observation.SourcePassiveARP, observation.SubjectMAC, "aa:bb:cc:00:00:01", observation.AttrIPBinding, "10.0.0.5", 95)
	rec(observation.SourceUniFi, observation.SubjectIPv4, "10.0.0.5", observation.AttrDHCPLease, "reserved", 90)

	if _, err := New(st, nil, testParams()).Rebuild(ctx); err != nil {
		t.Fatal(err)
	}
	snap, err := st.LoadEntities(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, a := range snap.Addresses {
		if a.IP == "10.0.0.5" {
			found = true
			if a.DHCP != "reserved" {
				t.Errorf("address DHCP = %q, want reserved", a.DHCP)
			}
		}
	}
	if !found {
		t.Fatal("address 10.0.0.5 not reconciled")
	}
}

// testT0 anchors the synthetic timeline; testClock is "now" just after it so
// addresses are active and confidences are barely decayed. A fixed clock makes
// the whole reconciliation deterministic (aging and decay are time-relative).
var testT0 = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
var testClock = testT0.Add(time.Minute)

func testParams() Params { return Params{Now: func() time.Time { return testClock }} }

// seed writes a fixed set of observations through the standard sink, in a
// deliberately shuffled append order (later observed_at appended first) to prove
// the reconciler orders by (observed_at, id), not by insert order.
func seed(t *testing.T, st store.Store) {
	t.Helper()
	ctx := context.Background()
	t0 := testT0
	arp := observation.NewSink("arp", st)
	probe := observation.NewSink("probe", st)

	rec := func(s *observation.Sink, src observation.Source, st_ observation.SubjectType, subj string, a observation.Attribute, v string, c int, ts time.Time) {
		if _, err := s.Record(ctx, src, st_, subj, a, v, c, observation.At(ts)); err != nil {
			t.Fatalf("record: %v", err)
		}
	}

	// Appended out of timestamp order on purpose.
	rec(arp, observation.SourcePassiveDHCP, observation.SubjectMAC, "B8:27:EB:11:22:33", observation.AttrHostname, "pihole", 80, t0.Add(time.Second))
	rec(arp, observation.SourcePassiveARP, observation.SubjectMAC, "b8:27:eb:11:22:33", observation.AttrIPBinding, "10.0.0.20", 95, t0)
	rec(arp, observation.SourcePassiveARP, observation.SubjectMAC, "aa:bb:cc:dd:ee:ff", observation.AttrIPBinding, "10.0.0.55", 95, t0.Add(2*time.Second))
	rec(arp, observation.SourcePassiveARP, observation.SubjectMAC, "aa:bb:cc:dd:ee:ff", observation.AttrOUIVendor, "SyntheticVendor", 90, t0.Add(2*time.Second))
	rec(probe, observation.SourceActiveICMP, observation.SubjectIPv4, "10.0.0.99", observation.AttrLiveness, "up", 85, t0.Add(3*time.Second))
	// device_class disagreement: UniFi (strong) "NAS" 70 vs Fingerbank (inferential) "SBC" 88.
	rec(arp, observation.SourceUniFi, observation.SubjectMAC, "b8:27:eb:11:22:33", observation.AttrDeviceClass, "NAS", 70, t0.Add(4*time.Second))
	rec(arp, observation.SourceFingerbank, observation.SubjectMAC, "b8:27:eb:11:22:33", observation.AttrDeviceClass, "SBC", 88, t0.Add(5*time.Second))
}

func TestRebuildDeterministic(t *testing.T) {
	st := newStore(t)
	seed(t, st)
	r := New(st, nil, testParams())
	ctx := context.Background()

	if _, err := r.Rebuild(ctx); err != nil {
		t.Fatalf("rebuild 1: %v", err)
	}
	snap1, err := st.LoadEntities(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// Replaying the unchanged log must reproduce an identical snapshot.
	if _, err := r.Rebuild(ctx); err != nil {
		t.Fatalf("rebuild 2: %v", err)
	}
	snap2, err := st.LoadEntities(ctx)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(snap1, snap2) {
		t.Fatalf("non-deterministic rebuild:\n%+v\n!=\n%+v", snap1, snap2)
	}
}

func TestRebuildEntities(t *testing.T) {
	st := newStore(t)
	seed(t, st)
	ctx := context.Background()
	if _, err := New(st, nil, testParams()).Rebuild(ctx); err != nil {
		t.Fatal(err)
	}
	snap, err := st.LoadEntities(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// 3 hosts: mac:b8:27:.., mac:aa:bb:.., ip:10.0.0.99 (provisional).
	if len(snap.Hosts) != 3 {
		t.Errorf("hosts = %d, want 3", len(snap.Hosts))
	}

	// The Pi host got a hostname and a vendor on a non-randomized iface.
	pi := findHost(snap.Hosts, "mac:b8:27:eb:11:22:33")
	if pi == nil || pi.DisplayName != "pihole" {
		t.Errorf("pi host/display_name wrong: %+v", pi)
	}
	// device_class winner: Fingerbank "SBC" (conf 88) beats UniFi "NAS" (conf 70)
	// on effective confidence, despite UniFi's higher tier (tier is only a tiebreak).
	if pi == nil || pi.DeviceClass != "SBC" {
		t.Errorf("pi device_class = %q, want SBC (higher confidence wins)", pi.DeviceClass)
	}
	if pi != nil && pi.Confidence < 80 {
		t.Errorf("pi confidence = %d, want ~88 (barely decayed, no randomized penalty)", pi.Confidence)
	}
	piIface := findIface(snap.Interfaces, "b8:27:eb:11:22:33")
	if piIface == nil || piIface.IsRandomized {
		t.Errorf("pi iface should not be randomized: %+v", piIface)
	}

	// The randomized MAC: flagged, and its (synthetic) OUI vendor was NOT trusted (§6).
	rnd := findIface(snap.Interfaces, "aa:bb:cc:dd:ee:ff")
	if rnd == nil || !rnd.IsRandomized {
		t.Fatalf("randomized iface not flagged: %+v", rnd)
	}
	if rnd.OUIVendor != "" {
		t.Errorf("randomized iface should not carry an OUI vendor, got %q", rnd.OUIVendor)
	}

	// Address binding: 10.0.0.20 → the Pi.
	a := findAddr(snap.Addresses, "10.0.0.20")
	if a == nil || a.MAC != "b8:27:eb:11:22:33" || a.HostID == nil {
		t.Errorf("address binding wrong: %+v", a)
	}
	if a.State != entity.StateActive {
		t.Errorf("address state = %q, want active", a.State)
	}
	// first_seen reflects the earliest supporting observation (ordering check).
	if !a.FirstSeen.Equal(time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)) {
		t.Errorf("address first_seen = %v, want t0", a.FirstSeen)
	}
}

func findHost(hs []entity.Host, stableID string) *entity.Host {
	for i := range hs {
		if hs[i].StableID == stableID {
			return &hs[i]
		}
	}
	return nil
}
func findIface(is []entity.Interface, mac string) *entity.Interface {
	for i := range is {
		if is[i].MAC == mac {
			return &is[i]
		}
	}
	return nil
}
func findAddr(as []entity.Address, ip string) *entity.Address {
	for i := range as {
		if as[i].IP == ip {
			return &as[i]
		}
	}
	return nil
}

// TestConflictRecorded asserts that a disagreement between two sources on a
// high-value attribute opens a conflict whose value_a is the current (winning)
// value and value_b is the disagreeing one — surfaced, not silently resolved.
func TestConflictRecorded(t *testing.T) {
	st := newStore(t)
	seed(t, st)
	ctx := context.Background()
	if _, err := New(st, nil, testParams()).Rebuild(ctx); err != nil {
		t.Fatal(err)
	}
	snap, err := st.LoadEntities(ctx)
	if err != nil {
		t.Fatal(err)
	}

	var c *entity.Conflict
	for i := range snap.Conflicts {
		if snap.Conflicts[i].Attribute == "device_class" {
			c = &snap.Conflicts[i]
		}
	}
	if c == nil {
		t.Fatal("expected a device_class conflict, got none")
	}
	// Winner (value_a) is SBC; the disagreeing value_b is NAS.
	if c.ValueA != "SBC" || c.SourceA != "fingerbank" {
		t.Errorf("conflict winner = %q/%q, want SBC/fingerbank", c.ValueA, c.SourceA)
	}
	if c.ValueB != "NAS" || c.SourceB != "unifi" {
		t.Errorf("conflict runner-up = %q/%q, want NAS/unifi", c.ValueB, c.SourceB)
	}
	if c.Subject != "mac:b8:27:eb:11:22:33" {
		t.Errorf("conflict subject = %q", c.Subject)
	}
	if c.Resolved {
		t.Error("new conflict should not be resolved")
	}
}

// TestSubnetSeedingAndMembership asserts the M3.5 contributions fold correctly:
// a subnet_hint seeds the subnets table, an address inside it gets subnet_id set
// by membership, and a switch_port observation produces a topology row.
func TestSubnetSeedingAndMembership(t *testing.T) {
	st := newStore(t)
	ctx := context.Background()
	uni := observation.NewSink("unifi", st)
	t0 := testT0

	// Configured network → subnet_hint (subject is the network address).
	vlan := 10
	hint := observation.SubnetHintValue{CIDR: "10.0.10.0/24", Name: "IoT", Gateway: "10.0.10.1", VLAN: &vlan}
	if _, err := uni.Record(ctx, observation.SourceUniFi, observation.SubjectIPv4, "10.0.10.0",
		observation.AttrSubnetHint, hint.MarshalValue(), 95, observation.At(t0)); err != nil {
		t.Fatal(err)
	}
	// A client in that subnet, with a switch-port mapping.
	if _, err := uni.Record(ctx, observation.SourceUniFi, observation.SubjectMAC, "b8:27:eb:11:22:33",
		observation.AttrIPBinding, "10.0.10.20", 90, observation.At(t0)); err != nil {
		t.Fatal(err)
	}
	if _, err := uni.Record(ctx, observation.SourceUniFi, observation.SubjectMAC, "b8:27:eb:11:22:33",
		observation.AttrSwitchPort, "f0:9f:c2:aa:bb:cc/5", 95, observation.At(t0)); err != nil {
		t.Fatal(err)
	}

	if _, err := New(st, nil, testParams()).Rebuild(ctx); err != nil {
		t.Fatal(err)
	}
	snap, err := st.LoadEntities(ctx)
	if err != nil {
		t.Fatal(err)
	}

	if len(snap.Subnets) != 1 {
		t.Fatalf("subnets = %d, want 1", len(snap.Subnets))
	}
	sn := snap.Subnets[0]
	if sn.CIDR != "10.0.10.0/24" || sn.Gateway != "10.0.10.1" || sn.Name != "IoT" {
		t.Errorf("subnet wrong: %+v", sn)
	}
	if sn.VLANID == nil || *sn.VLANID != 10 {
		t.Errorf("subnet vlan = %v, want 10", sn.VLANID)
	}

	a := findAddr(snap.Addresses, "10.0.10.20")
	if a == nil || a.SubnetID == nil {
		t.Fatalf("address not assigned to subnet: %+v", a)
	}
	if *a.SubnetID != sn.ID {
		t.Errorf("address subnet_id = %d, want %d", *a.SubnetID, sn.ID)
	}

	if len(snap.Topology) != 1 {
		t.Fatalf("topology = %d, want 1", len(snap.Topology))
	}
	tp := snap.Topology[0]
	if tp.Switch != "f0:9f:c2:aa:bb:cc" || tp.SwitchPort != "5" {
		t.Errorf("topology wrong: %+v", tp)
	}
}

// TestOUIFallback asserts the §7 offline OUI fallback: an interface with no
// oui_vendor observation gets its vendor from the bundled table, and a
// randomized MAC never does.
func TestOUIFallback(t *testing.T) {
	st := newStore(t)
	ctx := context.Background()
	arp := observation.NewSink("arp", st)
	// Pi MAC, no oui_vendor observation at all.
	if _, err := arp.Record(ctx, observation.SourcePassiveARP, observation.SubjectMAC,
		"b8:27:eb:99:88:77", observation.AttrIPBinding, "10.0.0.30", 95, observation.At(testT0)); err != nil {
		t.Fatal(err)
	}
	// Randomized MAC.
	if _, err := arp.Record(ctx, observation.SourcePassiveARP, observation.SubjectMAC,
		"aa:bb:cc:dd:ee:01", observation.AttrIPBinding, "10.0.0.31", 95, observation.At(testT0)); err != nil {
		t.Fatal(err)
	}
	if _, err := New(st, nil, testParams()).Rebuild(ctx); err != nil {
		t.Fatal(err)
	}
	snap, err := st.LoadEntities(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if i := findIface(snap.Interfaces, "b8:27:eb:99:88:77"); i == nil || i.OUIVendor != "Raspberry Pi Foundation" {
		t.Errorf("Pi iface vendor from OUI fallback wrong: %+v", i)
	}
	if i := findIface(snap.Interfaces, "aa:bb:cc:dd:ee:01"); i == nil || i.OUIVendor != "" {
		t.Errorf("randomized iface must not get a vendor: %+v", i)
	}
}

// TestActiveProbeServices asserts the M4 contributions fold: an open_port plus a
// service_banner produce a service row with the banner attached, and an SNMP
// os_guess (IP-subject) lands on the host.
func TestActiveProbeServices(t *testing.T) {
	st := newStore(t)
	ctx := context.Background()
	probe := observation.NewSink("active", st)
	t0 := testT0

	rec := func(src observation.Source, styp observation.SubjectType, subj string, a observation.Attribute, v string, c int) {
		if _, err := probe.Record(ctx, src, styp, subj, a, v, c, observation.At(t0)); err != nil {
			t.Fatal(err)
		}
	}
	// Liveness + binding so the host/address exist.
	rec(observation.SourceActiveARP, observation.SubjectMAC, "b8:27:eb:11:22:33", observation.AttrIPBinding, "10.0.0.20", 96)
	rec(observation.SourceActiveTCP, observation.SubjectIPv4, "10.0.0.20", observation.AttrOpenPort, "tcp/22", 85)
	rec(observation.SourceActiveTCP, observation.SubjectIPv4, "10.0.0.20", observation.AttrServiceBanner, "tcp/22|SSH-2.0-OpenSSH_9.0", 75)
	rec(observation.SourceActiveSNMP, observation.SubjectIPv4, "10.0.0.20", observation.AttrOSGuess, "Linux 5.10 armv7l", 70)

	if _, err := New(st, nil, testParams()).Rebuild(ctx); err != nil {
		t.Fatal(err)
	}
	snap, err := st.LoadEntities(ctx)
	if err != nil {
		t.Fatal(err)
	}

	if len(snap.Services) != 1 {
		t.Fatalf("services = %d, want 1", len(snap.Services))
	}
	sv := snap.Services[0]
	if sv.Proto != "tcp" || sv.Port != 22 || sv.Banner != "SSH-2.0-OpenSSH_9.0" {
		t.Errorf("service wrong: %+v", sv)
	}
	if sv.HostID == nil {
		t.Error("service should be linked to its host")
	}
	// SNMP os_guess folded onto the host (IP-subject classification).
	h := findHost(snap.Hosts, "mac:b8:27:eb:11:22:33")
	if h == nil || h.OSGuess != "Linux 5.10 armv7l" {
		t.Errorf("host os_guess = %q, want from SNMP", h.OSGuess)
	}
}

// TestAddressAging asserts the active→stale→free transitions as the clock moves
// past the configured thresholds, replaying the same log from empty each time.
func TestAddressAging(t *testing.T) {
	st := newStore(t)
	seed(t, st)
	ctx := context.Background()

	// The Pi binding's newest supporting observation is at t0 (10.0.0.20).
	cases := []struct {
		name string
		now  time.Time
		want entity.AddressState
	}{
		{"fresh", testT0.Add(time.Hour), entity.StateActive},
		{"stale", testT0.Add(48 * time.Hour), entity.StateStale}, // > 24h stale_after
		{"free", testT0.Add(200 * time.Hour), entity.StateFree},  // > 168h free_after
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			now := tc.now
			r := New(st, nil, Params{Now: func() time.Time { return now }})
			if _, err := r.Rebuild(ctx); err != nil {
				t.Fatal(err)
			}
			snap, err := st.LoadEntities(ctx)
			if err != nil {
				t.Fatal(err)
			}
			a := findAddr(snap.Addresses, "10.0.0.20")
			if a == nil {
				t.Fatal("address 10.0.0.20 missing")
			}
			if a.State != tc.want {
				t.Errorf("at %v: state = %q, want %q", tc.now, a.State, tc.want)
			}
		})
	}
}
