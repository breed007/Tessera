package unifi

import (
	_ "embed"
	"encoding/json"
	"strconv"
	"strings"
)

// UniFi fingerprints every client against its own device database and reports the
// match as a numeric `dev_id` (with `dev_id_override` taking precedence when an
// operator has corrected it). The id is meaningless without the lookup table, so
// we bundle a snapshot of it — the same way internal/oui bundles the OUI table —
// giving first-party device identification with ZERO external calls.
//
// fingerprint_devices.json is a flat {"<dev_id>": "<model name>"} map extracted
// from UniFi's public fingerprint database (≈5,500 entries). Source:
// https://github.com/CANTI-BOT/UniFi-Icon-Browser (chrome-extension/data).
// Refresh it by replacing the file; nothing else changes.

//go:embed fingerprint_devices.json
var fingerprintDevicesJSON []byte

// fingerprintDevices maps a UniFi dev_id to its human-readable model name.
var fingerprintDevices = mustLoadFingerprints(fingerprintDevicesJSON)

// unifi_models.json maps a UniFi gear MODEL CODE (the `model` field on a
// stat/device record, e.g. "U7PG2", "UDMPRO", "USL16P") to a recognizable model
// name ("UAP AC Pro", "UDM Pro", "USW 16 PoE"). This is the controller's own
// device list — without it, UniFi gear shows only a generic class derived from
// the coarse `type` ("uap"/"usw"/…). Source: the UniFi device database
// (github.com gist sgrodzicki/265273ff0ede952d6fcd1a1eedb6aa60, reduced to
// code→name). Refresh by replacing the file.

//go:embed unifi_models.json
var unifiModelsJSON []byte

// unifiModels maps a UniFi gear model code to its product name.
var unifiModels = mustLoadFingerprints(unifiModelsJSON)

// unifi_ports.json maps a product NAME (the resolved model, e.g. "USW Flex 2.5G
// 5") to its physical port count — so the port-map can draw empty ports too.
// Source: public.json unifi.network.numberOfPorts.

//go:embed unifi_ports.json
var unifiPortsJSON []byte

var unifiPorts = mustLoadPorts()

func mustLoadPorts() map[string]int {
	m := map[string]int{}
	_ = json.Unmarshal(unifiPortsJSON, &m)
	return m
}

// PortCount returns the physical port count for a resolved UniFi model name.
func PortCount(modelName string) (int, bool) {
	n, ok := unifiPorts[strings.TrimSpace(modelName)]
	return n, ok && n > 0
}

func mustLoadFingerprints(raw []byte) map[string]string {
	m := map[string]string{}
	// A malformed bundled file is a build/release problem, not a runtime one; an
	// empty map simply means no resolution (the poller still works).
	_ = json.Unmarshal(raw, &m)
	return m
}

// resolveUniFiModel turns a stat/device model code into its product name. Codes
// are upper-case in the controller and in the bundled table.
func resolveUniFiModel(code string) (string, bool) {
	code = strings.ToUpper(strings.TrimSpace(code))
	if code == "" {
		return "", false
	}
	if name, ok := unifiModels[code]; ok && name != "" {
		return name, true
	}
	// Tolerate punctuation/case differences between the controller's code and the
	// table keys (e.g. "USW-Pro-XG" vs "USWPROXG").
	norm := func(s string) string {
		var b strings.Builder
		for _, r := range strings.ToUpper(s) {
			if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
				b.WriteRune(r)
			}
		}
		return b.String()
	}
	want := norm(code)
	if name, ok := unifiModels[want]; ok && name != "" {
		return name, true
	}
	return "", false
}

// resolveDeviceModel returns the model name for a UniFi dev_id, preferring an
// operator override. A zero/unset id or an unknown id yields ("", false).
func resolveDeviceModel(devID, override flexInt) (string, bool) {
	id := ""
	switch {
	case override.Set && override.Val > 0:
		id = strconv.Itoa(override.Val)
	case devID.Set && devID.Val > 0:
		id = strconv.Itoa(devID.Val)
	default:
		return "", false
	}
	name, ok := fingerprintDevices[id]
	if !ok || strings.TrimSpace(name) == "" {
		return "", false
	}
	return name, true
}

// osFromModel derives an OS from a resolved model name where the name makes it
// unambiguous. It is deliberately conservative — an empty return just means "let
// another signal decide". This is the only place we infer OS from the UniFi
// fingerprint, since UniFi's separate os_name id has no bundled table.
func osFromModel(model string) string {
	m := strings.ToLower(model)
	switch {
	case strings.Contains(m, "apple tv"):
		return "tvOS"
	case strings.Contains(m, "apple watch"):
		return "watchOS"
	case containsAnyStr(m, "iphone", "ipad", "ipod"):
		return "iOS"
	case containsAnyStr(m, "macbook", "imac", "mac mini", "mac pro", "mac studio"):
		return "macOS"
	case containsAnyStr(m, "galaxy", "pixel", "android", "oneplus", "xiaomi", "redmi"):
		return "Android"
	case strings.Contains(m, "windows"):
		return "Windows"
	case strings.Contains(m, "chromebook"):
		return "ChromeOS"
	default:
		return ""
	}
}

func containsAnyStr(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
