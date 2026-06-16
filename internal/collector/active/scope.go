// Package active is the active prober (§4.2). It confirms liveness and fills
// gaps the passive sensor can't reach, using gentle, rate-limited, CONNECT-only
// probes — ARP-cache harvest, ICMP echo, reverse DNS, light TCP connect probes,
// and optional SNMP. It is strictly scoped to operator-configured subnets: never
// the whole internet, never unscoped (§4.2). It is explicitly NOT a port scanner
// or vulnerability scanner (§8) — connect scans only, no raw/SYN sockets.
package active

import (
	"fmt"
	"net/netip"
)

// maxTargets caps how many addresses a single sweep will enumerate across all
// configured subnets — a runaway-scope backstop. A /16 is 65534 hosts; anything
// past this is almost certainly a misconfiguration, not an intent.
const maxTargets = 65536

// enumerateTargets expands the configured CIDRs into the concrete IPv4 addresses
// to probe, skipping network and broadcast addresses. IPv6 prefixes can't be
// swept by enumeration and are skipped (reported via skipped). The total is
// capped at maxTargets; subnets that would exceed it are skipped, not truncated
// silently (§8: no silent caps).
func enumerateTargets(cidrs []string) (targets []netip.Addr, skipped []string, err error) {
	seen := make(map[netip.Addr]bool)
	for _, c := range cidrs {
		p, perr := netip.ParsePrefix(c)
		if perr != nil {
			return nil, nil, fmt.Errorf("active: bad subnet %q: %w", c, perr)
		}
		p = p.Masked()
		if p.Addr().Is6() {
			skipped = append(skipped, c+" (IPv6 sweep unsupported)")
			continue
		}
		hosts := hostCount(p)
		if hosts == 0 {
			continue
		}
		if len(targets)+hosts > maxTargets {
			skipped = append(skipped, fmt.Sprintf("%s (%d hosts exceeds remaining budget)", c, hosts))
			continue
		}
		for _, a := range expand4(p) {
			if !seen[a] {
				seen[a] = true
				targets = append(targets, a)
			}
		}
	}
	return targets, skipped, nil
}

// hostCount returns the number of usable host addresses in an IPv4 prefix.
func hostCount(p netip.Prefix) int {
	bits := p.Bits()
	switch {
	case bits >= 31: // /31 (point-to-point) and /32 → both addresses usable
		return 1 << (32 - bits)
	default:
		return (1 << (32 - bits)) - 2 // minus network + broadcast
	}
}

// expand4 yields the usable host addresses of an IPv4 prefix.
func expand4(p netip.Prefix) []netip.Addr {
	bits := p.Bits()
	size := uint32(1) << (32 - bits)
	base := beUint32(p.Addr())
	var out []netip.Addr
	for i := uint32(0); i < size; i++ {
		// For prefixes shorter than /31, skip the network (.0) and broadcast (.last).
		if bits < 31 && (i == 0 || i == size-1) {
			continue
		}
		out = append(out, uint32ToAddr(base+i))
	}
	return out
}

func beUint32(a netip.Addr) uint32 {
	b := a.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func uint32ToAddr(v uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}
