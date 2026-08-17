package export

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"strings"
	"testing"

	"github.com/breed007/Tessera/internal/entity"
)

func ptr[T any](v T) *T { return &v }

func fixture() entity.Snapshot {
	return entity.Snapshot{
		Subnets: []entity.Subnet{{ID: 1, CIDR: "10.0.0.0/24", Name: "LAN", Gateway: "10.0.0.1", Source: "unifi"}},
		Hosts:   []entity.Host{{ID: 1, StableID: "mac:b8:27:eb:11:22:33", DisplayName: "pi", DeviceClass: "SBC", Confidence: 88, IsExpected: true, Notes: "rack 1"}},
		Interfaces: []entity.Interface{
			{ID: 1, HostID: 1, MAC: "b8:27:eb:11:22:33", OUIVendor: "Raspberry Pi Foundation"},
		},
		Addresses: []entity.Address{
			{ID: 1, IP: "10.0.0.20", IPVersion: 4, SubnetID: ptr(int64(1)), HostID: ptr(int64(1)), MAC: "b8:27:eb:11:22:33", State: entity.StateActive},
			{ID: 2, IP: "10.0.0.99", IPVersion: 4, SubnetID: ptr(int64(1)), State: entity.StateFree},
		},
	}
}

func render(t *testing.T, name string) string {
	t.Helper()
	var buf bytes.Buffer
	if _, err := Write(&buf, name, fixture()); err != nil {
		t.Fatalf("Write(%s): %v", name, err)
	}
	return buf.String()
}

func TestInventoryJSON(t *testing.T) {
	var m map[string]any
	if err := json.Unmarshal([]byte(render(t, "inventory.json")), &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["hosts"]; !ok {
		t.Error("inventory json missing hosts")
	}
}

func TestHostsCSV(t *testing.T) {
	rows := parseCSV(t, render(t, "hosts.csv"))
	if rows[0][0] != "stable_id" {
		t.Fatalf("header = %v", rows[0])
	}
	row := rows[1]
	joined := strings.Join(row, "|")
	for _, want := range []string{"pi", "SBC", "Raspberry Pi Foundation", "true"} {
		if !strings.Contains(joined, want) {
			t.Errorf("hosts row missing %q: %v", want, row)
		}
	}
}

func TestNetBoxIPs(t *testing.T) {
	rows := parseCSV(t, render(t, "netbox-ips.csv"))
	if rows[0][0] != "address" {
		t.Fatalf("header = %v", rows[0])
	}
	// Active address carries the subnet prefix length and dns name; the free one
	// is omitted (NetBox treats unlisted as available).
	if len(rows) != 2 {
		t.Fatalf("expected header + 1 active row, got %d rows", len(rows))
	}
	if rows[1][0] != "10.0.0.20/24" || rows[1][1] != "active" || rows[1][2] != "pi" {
		t.Errorf("netbox ip row = %v", rows[1])
	}
}

func TestNetBoxPrefixes(t *testing.T) {
	rows := parseCSV(t, render(t, "netbox-prefixes.csv"))
	if rows[1][0] != "10.0.0.0/24" || rows[1][1] != "active" || rows[1][3] != "LAN" {
		t.Errorf("netbox prefix row = %v", rows[1])
	}
}

func TestPhpIPAM(t *testing.T) {
	rows := parseCSV(t, render(t, "phpipam-addresses.csv"))
	if rows[0][0] != "ip_addr" {
		t.Fatalf("header = %v", rows[0])
	}
	if rows[1][0] != "10.0.0.20" || rows[1][1] != "pi" {
		t.Errorf("phpipam row = %v", rows[1])
	}
}

func TestUnknownFormat(t *testing.T) {
	var buf bytes.Buffer
	if _, err := Write(&buf, "nope.xml", fixture()); err == nil {
		t.Error("unknown format should error")
	}
}

func parseCSV(t *testing.T, s string) [][]string {
	t.Helper()
	rows, err := csv.NewReader(strings.NewReader(s)).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) < 1 {
		t.Fatal("no rows")
	}
	return rows
}
