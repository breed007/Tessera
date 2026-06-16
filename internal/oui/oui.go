// Package oui provides an always-available, fully-offline IEEE OUI → vendor
// lookup (§7). Basic vendor attribution must never depend on any external
// service, so this table is bundled. The set below is a curated subset of common
// homelab vendors; a deployment can replace bundled.go with the full IEEE OUI
// registry (oui.csv) without changing the lookup API.
package oui

import (
	"strings"

	"github.com/tessera/tessera/internal/netid"
)

// Lookup returns the vendor for a normalized MAC's OUI prefix. It returns ok=false
// for unknown prefixes and for locally-administered (randomized) MACs, whose OUI
// is synthetic and must never be treated as a vendor signal (§6).
func Lookup(mac string) (vendor string, ok bool) {
	if mac == "" || netid.IsLocallyAdministered(mac) {
		return "", false
	}
	prefix := netid.OUI(mac)
	if prefix == "" {
		return "", false
	}
	v, ok := table[strings.ToLower(prefix)]
	return v, ok
}
