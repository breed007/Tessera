package passive

import (
	_ "embed"
	"encoding/json"
	"strings"
)

// Apple devices report a precise hardware identifier in their mDNS _device-info
// TXT `model=` record — either a model identifier ("Mac16,7", "iPhone17,1") or,
// on some newer Macs, a board id ("J516sAP"). Both forms resolve to the exact
// marketing name here, which is far more accurate than a vendor fingerprint
// (UniFi, for one, mis-dates newer Macs). The device is telling us exactly what
// it is, so a hit here outranks any inferential classifier.
//
// apple_models.json is a flat {identifier-or-board: marketing-name} map built
// from AppleDB (https://appledb.dev, api.appledb.dev/device/main.json). Refresh
// by replacing the file.

//go:embed apple_models.json
var appleModelsJSON []byte

var appleModels = mustLoadAppleModels()

func mustLoadAppleModels() map[string]string {
	m := map[string]string{}
	_ = json.Unmarshal(appleModelsJSON, &m)
	return m
}

// lookupAppleModel resolves a mDNS model= value to a marketing name, exact match
// only (identifiers and board ids are case-sensitive).
func lookupAppleModel(model string) (string, bool) {
	name, ok := appleModels[strings.TrimSpace(model)]
	return name, ok && name != ""
}

// appleOSForName derives the OS from a resolved marketing name (robust for both
// identifier and board-id inputs).
func appleOSForName(name string) string {
	switch {
	case strings.Contains(name, "Apple TV"):
		return "tvOS"
	case strings.Contains(name, "Apple Watch"):
		return "watchOS"
	case strings.Contains(name, "iPhone"), strings.Contains(name, "iPod"):
		return "iOS"
	case strings.Contains(name, "iPad"):
		return "iPadOS"
	case containsAnyStr(name, "MacBook", "iMac", "Mac mini", "Mac Studio", "Mac Pro"):
		return "macOS"
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
