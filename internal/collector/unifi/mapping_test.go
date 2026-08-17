package unifi

import (
	"testing"

	"github.com/breed007/Tessera/internal/observation"
)

// fixtures are trimmed but real-shaped private-API envelopes.
const clientsJSON = `{"meta":{"rc":"ok"},"data":[
  {"mac":"b8:27:eb:11:22:33","ip":"10.0.10.20","hostname":"pihole","oui":"Raspberry Pi","sw_mac":"f0:9f:c2:aa:bb:cc","sw_port":5,"vlan":10},
  {"mac":"aa:bb:cc:dd:ee:ff","name":"iPhone"},
  {"mac":"","ip":"10.0.10.99"}
]}`

const devicesJSON = `{"meta":{"rc":"ok"},"data":[
  {"mac":"f0:9f:c2:aa:bb:cc","ip":"10.0.10.2","name":"office-sw","type":"usw","model":"USW-24-PoE","version":"7.0.50"}
]}`

const networksJSON = `{"meta":{"rc":"ok"},"data":[
  {"name":"IoT","purpose":"corporate","ip_subnet":"10.0.10.1/24","vlan_enabled":true,"vlan":"10"},
  {"name":"Internet","purpose":"wan","ip_subnet":"203.0.113.2/30"}
]}`

func findEmit(es []emit, attr observation.Attribute, subject string) *emit {
	for i := range es {
		if es[i].attr == attr && es[i].subject == subject {
			return &es[i]
		}
	}
	return nil
}

func TestMapClients(t *testing.T) {
	var clients []clientDTO
	if err := decodeData([]byte(clientsJSON), &clients); err != nil {
		t.Fatal(err)
	}
	es := mapClients(clients)

	// MAC↔IP binding for the Pi.
	if e := findEmit(es, observation.AttrIPBinding, "b8:27:eb:11:22:33"); e == nil || e.value != "10.0.10.20" {
		t.Errorf("missing/incorrect ip_binding: %+v", e)
	}
	// switch port↔MAC → topology, encoded "<switch-mac>/<port>".
	if e := findEmit(es, observation.AttrSwitchPort, "b8:27:eb:11:22:33"); e == nil || e.value != "f0:9f:c2:aa:bb:cc/5" {
		t.Errorf("missing/incorrect switch_port: %+v", e)
	}
	// VLAN parsed even though it arrived as a string in networkconf-style data.
	if e := findEmit(es, observation.AttrVLANMembership, "b8:27:eb:11:22:33"); e == nil || e.value != "10" {
		t.Errorf("missing/incorrect vlan_membership: %+v", e)
	}
	// Client with name only → hostname, no binding.
	if e := findEmit(es, observation.AttrHostname, "aa:bb:cc:dd:ee:ff"); e == nil || e.value != "iPhone" {
		t.Errorf("missing/incorrect hostname: %+v", e)
	}
	// Client with empty MAC is skipped entirely.
	for _, e := range es {
		if e.subject == "" {
			t.Errorf("empty-MAC client should be skipped, got %+v", e)
		}
	}
}

func TestMapClientsDHCP(t *testing.T) {
	es := mapClients([]clientDTO{
		{MAC: "aa:aa:aa:aa:aa:aa", IP: "10.0.0.5"},                                        // dynamic
		{MAC: "bb:bb:bb:bb:bb:bb", IP: "10.0.0.6", UseFixedIP: true, FixedIP: "10.0.0.6"}, // reserved
	})
	if e := findEmit(es, observation.AttrDHCPLease, "10.0.0.5"); e == nil || e.value != "dynamic" {
		t.Errorf("dynamic lease emit = %+v, want dynamic", e)
	}
	if e := findEmit(es, observation.AttrDHCPLease, "10.0.0.6"); e == nil || e.value != "reserved" {
		t.Errorf("reserved lease emit = %+v, want reserved", e)
	}
}

const fingerprintClientsJSON = `{"meta":{"rc":"ok"},"data":[
  {"mac":"aa:bb:cc:00:00:14","ip":"10.0.0.121","name":"Apple TV 4K Den","oui":"Apple","dev_id":14},
  {"mac":"11:22:33:44:55:66","ip":"192.168.10.50","dev_id":4,"dev_id_override":7},
  {"mac":"99:88:77:66:55:44","ip":"192.168.10.51","dev_id":0}
]}`

func TestMapClientsFingerprint(t *testing.T) {
	var clients []clientDTO
	if err := decodeData([]byte(fingerprintClientsJSON), &clients); err != nil {
		t.Fatal(err)
	}
	es := mapClients(clients)

	// dev_id 14 → "Apple TV HD" → model, and tvOS derived from the model.
	if e := findEmit(es, observation.AttrModel, "aa:bb:cc:00:00:14"); e == nil || e.value != "Apple TV HD" {
		t.Errorf("fingerprint model wrong: %+v", e)
	}
	if e := findEmit(es, observation.AttrOSGuess, "aa:bb:cc:00:00:14"); e == nil || e.value != "tvOS" {
		t.Errorf("fingerprint os_guess wrong: %+v", e)
	}
	// dev_id_override (7 → "Apple iPhone SE") wins over dev_id (4 → iPhone 7).
	if e := findEmit(es, observation.AttrModel, "11:22:33:44:55:66"); e == nil || e.value != "Apple iPhone SE" {
		t.Errorf("override should win: %+v", e)
	}
	if e := findEmit(es, observation.AttrOSGuess, "11:22:33:44:55:66"); e == nil || e.value != "iOS" {
		t.Errorf("iphone os_guess wrong: %+v", e)
	}
	// dev_id 0 (unset) → no fingerprint observation.
	if e := findEmit(es, observation.AttrModel, "99:88:77:66:55:44"); e != nil {
		t.Errorf("dev_id 0 should not emit a model: %+v", e)
	}
}

func TestResolveDeviceModel(t *testing.T) {
	// Bundled DB sanity: a known id resolves, override precedence holds, unset is a miss.
	if name, ok := resolveDeviceModel(flexInt{Set: true, Val: 13}, flexInt{}); !ok || name != "Apple iMac" {
		t.Errorf("dev_id 13 = %q,%v want Apple iMac,true", name, ok)
	}
	if name, ok := resolveDeviceModel(flexInt{Set: true, Val: 13}, flexInt{Set: true, Val: 14}); !ok || name != "Apple TV HD" {
		t.Errorf("override 14 = %q,%v want Apple TV HD,true", name, ok)
	}
	if _, ok := resolveDeviceModel(flexInt{}, flexInt{}); ok {
		t.Error("unset dev_id should miss")
	}
	if _, ok := resolveDeviceModel(flexInt{Set: true, Val: 99999999}, flexInt{}); ok {
		t.Error("unknown dev_id should miss")
	}
}

func TestMapDevices(t *testing.T) {
	var devices []deviceDTO
	if err := decodeData([]byte(devicesJSON), &devices); err != nil {
		t.Fatal(err)
	}
	es := mapDevices(devices)
	// device_class is the coarse class; the specific product name is the model.
	if e := findEmit(es, observation.AttrDeviceClass, "f0:9f:c2:aa:bb:cc"); e == nil || e.value != "UniFi Switch" {
		t.Errorf("device_class wrong: %+v", e)
	}
	if e := findEmit(es, observation.AttrModel, "f0:9f:c2:aa:bb:cc"); e == nil || e.value != "USW 24 PoE" {
		t.Errorf("model wrong: %+v", e)
	}
	if e := findEmit(es, observation.AttrHostname, "f0:9f:c2:aa:bb:cc"); e == nil || e.value != "office-sw" {
		t.Errorf("device hostname wrong: %+v", e)
	}
	if e := findEmit(es, observation.AttrFirmware, "f0:9f:c2:aa:bb:cc"); e == nil || e.value != "7.0.50" {
		t.Errorf("firmware wrong: %+v", e)
	}
}

const modelDevicesJSON = `{"meta":{"rc":"ok"},"data":[
  {"mac":"f0:9f:c2:00:00:01","ip":"10.0.10.3","name":"oasis","type":"uap","model":"U7PG2"},
  {"mac":"f0:9f:c2:00:00:02","ip":"10.0.10.1","name":"gateway","type":"udm","model":"UDMPRO"},
  {"mac":"f0:9f:c2:00:00:03","ip":"10.0.10.4","name":"mystery","type":"usw","model":"ZZ-UNKNOWN-99"},
  {"mac":"f0:9f:c2:00:00:04","ip":"10.0.10.22","name":"symphony","type":"uap","model":"U7PROXG"}
]}`

func TestMapDevicesModel(t *testing.T) {
	var devices []deviceDTO
	if err := decodeData([]byte(modelDevicesJSON), &devices); err != nil {
		t.Fatal(err)
	}
	es := mapDevices(devices)
	// Known model codes resolve to the specific product name (the model field).
	if e := findEmit(es, observation.AttrModel, "f0:9f:c2:00:00:01"); e == nil || e.value != "AC Pro" {
		t.Errorf("AP model wrong: %+v", e)
	}
	if e := findEmit(es, observation.AttrModel, "f0:9f:c2:00:00:02"); e == nil || e.value != "UDM Pro" {
		t.Errorf("gateway model wrong: %+v", e)
	}
	// The coarse class always comes from the device type.
	if e := findEmit(es, observation.AttrDeviceClass, "f0:9f:c2:00:00:01"); e == nil || e.value != "UniFi Access Point" {
		t.Errorf("AP class wrong: %+v", e)
	}
	// Unknown model code → coarse class from type, and the RAW code surfaced as the
	// model (so a table gap is visible/reportable rather than silently dropped).
	if e := findEmit(es, observation.AttrDeviceClass, "f0:9f:c2:00:00:03"); e == nil || e.value != "UniFi Switch" {
		t.Errorf("unknown model class wrong: %+v", e)
	}
	if e := findEmit(es, observation.AttrModel, "f0:9f:c2:00:00:03"); e == nil || e.value != "ZZ-UNKNOWN-99" {
		t.Errorf("unknown model should surface the raw code: %+v", e)
	}
	// WiFi-7 gear resolves from the current official DB (was missing from the old table).
	if e := findEmit(es, observation.AttrModel, "f0:9f:c2:00:00:04"); e == nil || e.value != "U7 Pro XG" {
		t.Errorf("WiFi-7 model wrong: %+v", e)
	}
}

func TestMapDevicesModelDisplay(t *testing.T) {
	// When the controller provides a friendly model_display, it wins over the code.
	const j = `{"meta":{"rc":"ok"},"data":[
	  {"mac":"f0:9f:c2:00:00:09","ip":"10.0.10.9","name":"sw","type":"usw","model":"ZZUNKNOWN","model_display":"USW Flex 2.5G 5"}
	]}`
	var devices []deviceDTO
	if err := decodeData([]byte(j), &devices); err != nil {
		t.Fatal(err)
	}
	es := mapDevices(devices)
	if e := findEmit(es, observation.AttrModel, "f0:9f:c2:00:00:09"); e == nil || e.value != "USW Flex 2.5G 5" {
		t.Errorf("model_display should win: %+v", e)
	}
}

func TestResolveUniFiModel(t *testing.T) {
	if name, ok := resolveUniFiModel("udmpro"); !ok || name != "UDM Pro" { // case-insensitive
		t.Errorf("udmpro = %q,%v want UDM Pro,true", name, ok)
	}
	// The ACTUAL stat/device model codes (unifi.network.model, e.g. "USWED77")
	// must resolve — not just the marketing shortnames.
	for code, want := range map[string]string{
		"USWED77": "USW Pro XG 10 PoE", "USWED35": "USW Flex 2.5G 5", "USWED37": "USW Flex 2.5G 8 PoE",
	} {
		if name, ok := resolveUniFiModel(code); !ok || name != want {
			t.Errorf("%s = %q,%v want %q", code, name, ok, want)
		}
	}
	if _, ok := resolveUniFiModel("NOPE"); ok {
		t.Error("unknown code should miss")
	}
	if _, ok := resolveUniFiModel(""); ok {
		t.Error("empty code should miss")
	}
}

func TestMapNetworks(t *testing.T) {
	var networks []networkDTO
	if err := decodeData([]byte(networksJSON), &networks); err != nil {
		t.Fatal(err)
	}
	es := mapNetworks(networks)

	// WAN is skipped; only the corporate network yields a subnet_hint.
	if len(es) != 1 {
		t.Fatalf("expected 1 subnet_hint (WAN skipped), got %d: %+v", len(es), es)
	}
	e := es[0]
	if e.attr != observation.AttrSubnetHint {
		t.Fatalf("expected subnet_hint, got %s", e.attr)
	}
	// Subject is the NETWORK address (not the gateway).
	if e.subject != "10.0.10.0" {
		t.Errorf("subnet_hint subject = %q, want 10.0.10.0", e.subject)
	}
	hint, err := observation.ParseSubnetHint(e.value)
	if err != nil {
		t.Fatal(err)
	}
	if hint.CIDR != "10.0.10.0/24" {
		t.Errorf("cidr = %q, want 10.0.10.0/24", hint.CIDR)
	}
	if hint.Gateway != "10.0.10.1" {
		t.Errorf("gateway = %q, want 10.0.10.1", hint.Gateway)
	}
	if hint.VLAN == nil || *hint.VLAN != 10 {
		t.Errorf("vlan = %v, want 10", hint.VLAN)
	}
}
