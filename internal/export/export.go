// Package export renders the reconciled inventory to interchange formats (§M7):
// generic JSON/CSV, plus NetBox- and phpIPAM-shaped CSV import files so Tessera
// can FEED an existing IPAM one-way. It is export-file based by design — Tessera
// never writes to those systems directly (consistent with its read-only,
// no-external-writes posture); the operator imports the generated files.
package export

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"sort"
	"strconv"
	"time"

	"github.com/tessera/tessera/internal/entity"
)

// Spec describes one export format.
type Spec struct {
	Name        string
	ContentType string
	FileName    string
	gen         func(io.Writer, entity.Snapshot) error
}

var registry = []Spec{
	{"inventory.json", "application/json", "tessera-inventory.json", genInventoryJSON},
	{"hosts.csv", "text/csv", "tessera-hosts.csv", genHostsCSV},
	{"addresses.csv", "text/csv", "tessera-addresses.csv", genAddressesCSV},
	{"subnets.csv", "text/csv", "tessera-subnets.csv", genSubnetsCSV},
	{"netbox-ips.csv", "text/csv", "netbox-ip-addresses.csv", genNetBoxIPs},
	{"netbox-prefixes.csv", "text/csv", "netbox-prefixes.csv", genNetBoxPrefixes},
	{"phpipam-addresses.csv", "text/csv", "phpipam-addresses.csv", genPhpIPAMAddresses},
}

// Lookup returns the spec for a named format.
func Lookup(name string) (Spec, bool) {
	for _, s := range registry {
		if s.Name == name {
			return s, true
		}
	}
	return Spec{}, false
}

// Names lists the available export format names.
func Names() []string {
	out := make([]string, len(registry))
	for i, s := range registry {
		out[i] = s.Name
	}
	return out
}

// Write renders the named format to w. Returns the spec (for HTTP headers).
func Write(w io.Writer, name string, snap entity.Snapshot) (Spec, error) {
	s, ok := Lookup(name)
	if !ok {
		return Spec{}, fmt.Errorf("export: unknown format %q (have: %v)", name, Names())
	}
	return s, s.gen(w, snap)
}

// ── generic JSON ─────────────────────────────────────────────────────────────

func genInventoryJSON(w io.Writer, snap entity.Snapshot) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(snap)
}

// ── generic CSV ──────────────────────────────────────────────────────────────

func genHostsCSV(w io.Writer, snap entity.Snapshot) error {
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"stable_id", "display_name", "device_class", "os_guess", "confidence", "is_expected", "notes", "macs", "ips", "vendor", "first_seen", "last_seen"})
	macs, ips, vendor := hostIdentities(snap)
	for _, h := range snap.Hosts {
		_ = cw.Write([]string{
			h.StableID, h.DisplayName, h.DeviceClass, h.OSGuess, strconv.Itoa(h.Confidence),
			boolStr(h.IsExpected), h.Notes, joinSlash(macs[h.ID]), joinSlash(ips[h.ID]), vendor[h.ID],
			ts(h.FirstSeen), ts(h.LastSeen),
		})
	}
	cw.Flush()
	return cw.Error()
}

func genAddressesCSV(w io.Writer, snap entity.Snapshot) error {
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"ip", "ip_version", "state", "mac", "host", "subnet", "first_seen", "last_seen"})
	hostByID := hostByID(snap)
	subnetByID := subnetByID(snap)
	for _, a := range snap.Addresses {
		host := ""
		if a.HostID != nil {
			host = hostLabel(hostByID[*a.HostID])
		}
		subnet := ""
		if a.SubnetID != nil {
			subnet = subnetByID[*a.SubnetID].CIDR
		}
		_ = cw.Write([]string{a.IP, strconv.Itoa(a.IPVersion), string(a.State), a.MAC, host, subnet, ts(a.FirstSeen), ts(a.LastSeen)})
	}
	cw.Flush()
	return cw.Error()
}

func genSubnetsCSV(w io.Writer, snap entity.Snapshot) error {
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"cidr", "vlan_id", "name", "gateway", "source", "first_seen", "last_seen"})
	for _, s := range snap.Subnets {
		_ = cw.Write([]string{s.CIDR, intPtr(s.VLANID), s.Name, s.Gateway, s.Source, ts(s.FirstSeen), ts(s.LastSeen)})
	}
	cw.Flush()
	return cw.Error()
}

// ── NetBox import CSV ────────────────────────────────────────────────────────
// NetBox IPAM bulk-import columns. Free addresses are omitted (NetBox treats
// unlisted addresses in a prefix as available).

func genNetBoxIPs(w io.Writer, snap entity.Snapshot) error {
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"address", "status", "dns_name", "description"})
	hostByID := hostByID(snap)
	prefixLen := addressPrefixLen(snap)
	for _, a := range snap.Addresses {
		status := netboxStatus(a.State)
		if status == "" {
			continue // skip free/available
		}
		addr := a.IP + "/" + strconv.Itoa(prefixLen[a.IP])
		dns, desc := "", ""
		if a.HostID != nil {
			h := hostByID[*a.HostID]
			dns = h.DisplayName
			desc = describeHost(h)
		}
		_ = cw.Write([]string{addr, status, dns, desc})
	}
	cw.Flush()
	return cw.Error()
}

func genNetBoxPrefixes(w io.Writer, snap entity.Snapshot) error {
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"prefix", "status", "vlan", "description"})
	for _, s := range snap.Subnets {
		_ = cw.Write([]string{s.CIDR, "active", intPtr(s.VLANID), s.Name})
	}
	cw.Flush()
	return cw.Error()
}

// ── phpIPAM import CSV ───────────────────────────────────────────────────────
// phpIPAM's per-subnet address import. Column names vary by version; this is the
// common shape and may need light mapping on import.

func genPhpIPAMAddresses(w io.Writer, snap entity.Snapshot) error {
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"ip_addr", "hostname", "mac", "description", "state"})
	hostByID := hostByID(snap)
	for _, a := range snap.Addresses {
		hostname, desc := "", ""
		if a.HostID != nil {
			h := hostByID[*a.HostID]
			hostname = h.DisplayName
			desc = describeHost(h)
		}
		_ = cw.Write([]string{a.IP, hostname, a.MAC, desc, phpipamState(a.State)})
	}
	cw.Flush()
	return cw.Error()
}

// ── helpers ──────────────────────────────────────────────────────────────────

func hostByID(snap entity.Snapshot) map[int64]entity.Host {
	m := make(map[int64]entity.Host, len(snap.Hosts))
	for _, h := range snap.Hosts {
		m[h.ID] = h
	}
	return m
}

func subnetByID(snap entity.Snapshot) map[int64]entity.Subnet {
	m := make(map[int64]entity.Subnet, len(snap.Subnets))
	for _, s := range snap.Subnets {
		m[s.ID] = s
	}
	return m
}

func hostIdentities(snap entity.Snapshot) (macs, ips map[int64][]string, vendor map[int64]string) {
	macs, ips, vendor = map[int64][]string{}, map[int64][]string{}, map[int64]string{}
	for _, i := range snap.Interfaces {
		macs[i.HostID] = append(macs[i.HostID], i.MAC)
		if vendor[i.HostID] == "" {
			vendor[i.HostID] = i.OUIVendor
		}
	}
	for _, a := range snap.Addresses {
		if a.HostID != nil {
			ips[*a.HostID] = append(ips[*a.HostID], a.IP)
		}
	}
	return
}

// addressPrefixLen maps each address IP to the prefix length of its subnet (or
// the host length /32 or /128 when no subnet is known).
func addressPrefixLen(snap entity.Snapshot) map[string]int {
	subnetByID := subnetByID(snap)
	out := make(map[string]int, len(snap.Addresses))
	for _, a := range snap.Addresses {
		ones := 32
		if a.IPVersion == 6 {
			ones = 128
		}
		if a.SubnetID != nil {
			if p, err := netip.ParsePrefix(subnetByID[*a.SubnetID].CIDR); err == nil {
				ones = p.Bits()
			}
		}
		out[a.IP] = ones
	}
	return out
}

func hostLabel(h entity.Host) string {
	if h.DisplayName != "" {
		return h.DisplayName
	}
	return h.StableID
}

func describeHost(h entity.Host) string {
	parts := make([]string, 0, 2)
	if h.DeviceClass != "" {
		parts = append(parts, h.DeviceClass)
	}
	if h.Notes != "" {
		parts = append(parts, h.Notes)
	}
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += " — "
		}
		out += p
	}
	return out
}

func netboxStatus(s entity.AddressState) string {
	switch s {
	case entity.StateActive:
		return "active"
	case entity.StateReserved:
		return "reserved"
	case entity.StateStale:
		return "deprecated"
	default: // free → available, not imported
		return ""
	}
}

func phpipamState(s entity.AddressState) string {
	switch s {
	case entity.StateReserved:
		return "Reserved"
	case entity.StateActive:
		return "Online"
	default:
		return "Offline"
	}
}

func ts(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}
func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
func intPtr(p *int) string {
	if p == nil {
		return ""
	}
	return strconv.Itoa(*p)
}
func joinSlash(v []string) string {
	sort.Strings(v)
	out := ""
	for i, s := range v {
		if i > 0 {
			out += " / "
		}
		out += s
	}
	return out
}
