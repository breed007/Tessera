package observation

import "encoding/json"

// Some attributes carry structured JSON in their value rather than a bare
// string. These payload types are the shared vocabulary between the collector
// that emits them and the reconciler that folds them, so the encoding can't
// drift between the two sides.

// SubnetHintValue is the value payload for an AttrSubnetHint observation: a
// configured network discovered by UniFi (or entered manually) that seeds the
// subnets table (§4.3). The observation's subject is the network address.
type SubnetHintValue struct {
	CIDR    string `json:"cidr"`              // e.g. "10.0.10.0/24"
	VLAN    *int   `json:"vlan,omitempty"`    // VLAN id, if the network is tagged
	Name    string `json:"name,omitempty"`    // human network name
	Gateway string `json:"gateway,omitempty"` // gateway IP
}

// MarshalValue renders the payload as a value string for Sink.Record.
func (s SubnetHintValue) MarshalValue() string {
	b, _ := json.Marshal(s)
	return string(b)
}

// ParseSubnetHint decodes an AttrSubnetHint value payload.
func ParseSubnetHint(value string) (SubnetHintValue, error) {
	var v SubnetHintValue
	err := json.Unmarshal([]byte(value), &v)
	return v, err
}
