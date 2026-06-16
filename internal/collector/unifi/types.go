// Package unifi is the read-only UniFi controller poller (§4.3). It is a
// goldmine of first-party data the wire can't give us: the switch port↔MAC
// table (→ topology), the configured networks (→ seed subnets), and UniFi's own
// client fingerprints (→ classification observations that corroborate or
// conflict with wire-derived ones). It NEVER writes to the controller and never
// requests secret fields (a read-only role hides WPA keys — that's fine, we want
// inventory, not secrets).
package unifi

import (
	"encoding/json"
	"strconv"
	"strings"
)

// envelope is the standard private-API response wrapper: {"meta":{...},"data":[...]}.
type envelope struct {
	Meta struct {
		RC  string `json:"rc"`
		Msg string `json:"msg"`
	} `json:"meta"`
	Data json.RawMessage `json:"data"`
}

// flexInt tolerates a JSON field that may arrive as a number or a quoted string
// (UniFi is inconsistent across versions/endpoints, e.g. vlan). A value that
// can't be parsed is simply left unset rather than failing the whole response.
type flexInt struct {
	Set bool
	Val int
}

func (f *flexInt) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "" || s == "null" {
		return nil
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return nil // tolerate non-integer junk
	}
	f.Val, f.Set = n, true
	return nil
}

// clientDTO is a subset of a UniFi client record (stat/sta) — the fields we map
// to observations. We deliberately ignore everything else (no secrets here).
type clientDTO struct {
	MAC        string  `json:"mac"`
	IP         string  `json:"ip"`
	FixedIP    string  `json:"fixed_ip"`
	UseFixedIP bool    `json:"use_fixedip"`
	Hostname   string  `json:"hostname"`
	Name       string  `json:"name"`
	OUI        string  `json:"oui"`
	Network    string  `json:"network"`
	SwMAC      string  `json:"sw_mac"`
	SwPort     flexInt `json:"sw_port"`
	VLAN       flexInt `json:"vlan"`
	// Fingerprint: UniFi's own client identification. dev_id indexes the bundled
	// device database (→ a model name); dev_id_override is the operator-corrected
	// value and wins when present. See fpdb.go.
	DevID         flexInt `json:"dev_id"`
	DevIDOverride flexInt `json:"dev_id_override"`
}

// deviceDTO is a subset of a UniFi device record (stat/device) — the UniFi gear
// itself (APs, switches, gateways).
type deviceDTO struct {
	MAC   string `json:"mac"`
	IP    string `json:"ip"`
	Name  string `json:"name"`
	Model string `json:"model"`
	Type  string `json:"type"` // usw | uap | ugw | udm | uxg ...
}

// networkDTO is a subset of a configured network (rest/networkconf).
type networkDTO struct {
	Name        string  `json:"name"`
	Purpose     string  `json:"purpose"`   // corporate | guest | wan | vlan-only
	IPSubnet    string  `json:"ip_subnet"` // gateway/cidr, e.g. "10.0.10.1/24"
	VLANEnabled bool    `json:"vlan_enabled"`
	VLAN        flexInt `json:"vlan"`
}
