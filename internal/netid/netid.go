// Package netid normalizes the network identifiers (MAC, IP) that flow through
// the observation log, so the same device is keyed identically no matter which
// collector saw it. It also exposes the MAC-randomization signal (§6) used by
// the reconciler — the locally-administered bit in the first octet.
package netid

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// NormalizeMAC canonicalizes a MAC address to lowercase colon form
// (aa:bb:cc:dd:ee:ff). It accepts the usual hex separators (':', '-', '.').
func NormalizeMAC(s string) (string, error) {
	hw, err := net.ParseMAC(strings.TrimSpace(s))
	if err != nil {
		return "", fmt.Errorf("netid: parse mac %q: %w", s, err)
	}
	if len(hw) != 6 {
		return "", fmt.Errorf("netid: %q is not a 48-bit MAC", s)
	}
	return strings.ToLower(hw.String()), nil
}

// IsLocallyAdministered reports whether a normalized MAC has the U/L bit set in
// the first octet — the marker for a locally-administered (often randomized)
// address (§6). Callers must treat OUI as synthetic for these.
func IsLocallyAdministered(normMAC string) bool {
	if len(normMAC) < 2 {
		return false
	}
	var first int
	if _, err := fmt.Sscanf(normMAC[:2], "%02x", &first); err != nil {
		return false
	}
	return first&0x02 != 0 // bit 1 of the first octet is the U/L bit
}

// OUI returns the first three octets of a normalized MAC (the vendor prefix),
// e.g. "aa:bb:cc". For locally-administered MACs this is synthetic and must not
// be used as a vendor signal.
func OUI(normMAC string) string {
	parts := strings.SplitN(normMAC, ":", 4)
	if len(parts) < 3 {
		return ""
	}
	return strings.Join(parts[:3], ":")
}

// NormalizeIP canonicalizes an IP address and reports its version (4 or 6).
func NormalizeIP(s string) (canonical string, version int, err error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return "", 0, fmt.Errorf("netid: parse ip %q: %w", s, err)
	}
	addr = addr.Unmap() // collapse IPv4-in-IPv6 to plain IPv4
	if addr.Is4() {
		return addr.String(), 4, nil
	}
	return addr.String(), 6, nil
}
