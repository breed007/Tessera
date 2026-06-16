package active

import (
	"fmt"
	"net"
	"net/netip"
)

// Active probes must originate from the server's management interface and NEVER
// from a capture/SPAN/tap NIC (§4.1: the mirror destination is RX-only and often
// TX-disabled). This file resolves the source IP to bind every probe to, so
// egress is pinned to one interface — the default-route interface by default, or
// an explicitly named one.

// resolveSourceIP returns the IPv4 source address probes should bind to. If
// ifaceName is set, it uses that interface's address; otherwise it auto-detects
// the default-route (management) interface. desc is a human label for logging.
func resolveSourceIP(ifaceName string) (addr netip.Addr, desc string, err error) {
	if ifaceName != "" {
		a, err := interfaceSourceIP(ifaceName)
		return a, ifaceName, err
	}
	a, err := defaultSourceIP()
	return a, "default-route", err
}

// defaultSourceIP returns the IPv4 address the OS would use to reach off-link
// destinations — i.e. the default-route interface's source address. It opens a
// UDP socket "toward" a public address and reads the local binding the kernel
// chose; UDP connect performs only a route lookup, so NO packet is sent.
func defaultSourceIP() (netip.Addr, error) {
	c, err := net.Dial("udp4", "8.8.8.8:80")
	if err != nil {
		return netip.Addr{}, fmt.Errorf("active: detect default source ip: %w", err)
	}
	defer c.Close()
	ua, ok := c.LocalAddr().(*net.UDPAddr)
	if !ok {
		return netip.Addr{}, fmt.Errorf("active: unexpected local addr type")
	}
	a, ok := netip.AddrFromSlice(ua.IP)
	if !ok {
		return netip.Addr{}, fmt.Errorf("active: bad local addr")
	}
	return a.Unmap(), nil
}

// interfaceSourceIP returns the first usable (global unicast) IPv4 address of the
// named interface.
func interfaceSourceIP(name string) (netip.Addr, error) {
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("active: interface %q: %w", name, err)
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		return netip.Addr{}, fmt.Errorf("active: addrs for %q: %w", name, err)
	}
	for _, ad := range addrs {
		ipnet, ok := ad.(*net.IPNet)
		if !ok {
			continue
		}
		ip4 := ipnet.IP.To4()
		if ip4 == nil {
			continue
		}
		a, ok := netip.AddrFromSlice(ip4)
		if ok && a.IsGlobalUnicast() && !a.IsLinkLocalUnicast() {
			return a.Unmap(), nil
		}
	}
	return netip.Addr{}, fmt.Errorf("active: interface %q has no usable IPv4 address", name)
}
