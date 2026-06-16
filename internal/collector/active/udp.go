package active

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"syscall"
	"time"
)

// udpResult is the outcome of a single connected-UDP probe.
type udpResult struct {
	open    bool // a datagram came back → the service is listening
	refused bool // ICMP port-unreachable (surfaced as ECONNREFUSED) → host alive, port closed
}

func (r udpResult) alive() bool { return r.open || r.refused }

// udpPayloads holds a service-appropriate probe payload for well-known UDP
// ports. A tailored payload greatly raises the odds the service answers (which
// proves the port open). Ports not listed get a single null byte — enough to
// draw an ICMP port-unreachable from a closed port (→ host alive), though a live
// service may stay silent. UDP scanning is inherently lossy; a timeout is
// inconclusive and recorded as nothing (absence is never a fact, §4.2).
var udpPayloads = map[int][]byte{
	53:   dnsRootQuery(),
	123:  ntpClientRequest(),
	1900: ssdpMSearch(),
	5353: mdnsServicesQuery(),
}

// probeUDP sends one datagram to ip:port on a connected UDP socket and waits for
// a reply. localIP, when valid, pins the source address to the management
// interface so probes never egress a capture NIC (§4.1).
func probeUDP(ctx context.Context, ip string, port int, timeout time.Duration, localIP netip.Addr) udpResult {
	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	d := net.Dialer{Timeout: 2 * time.Second}
	if localIP.IsValid() {
		d.LocalAddr = &net.UDPAddr{IP: localIP.AsSlice()}
	}
	conn, err := d.DialContext(ctx, "udp", addr)
	if err != nil {
		return udpResult{}
	}
	defer conn.Close()

	payload := udpPayloads[port]
	if payload == nil {
		payload = []byte{0x00}
	}
	if _, err := conn.Write(payload); err != nil {
		return udpResult{refused: errors.Is(err, syscall.ECONNREFUSED)}
	}
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	switch {
	case n > 0:
		return udpResult{open: true}
	case errors.Is(err, syscall.ECONNREFUSED):
		return udpResult{refused: true}
	default:
		return udpResult{} // timeout / open|filtered — inconclusive
	}
}

// ── probe payloads ───────────────────────────────────────────────────────────

// dnsRootQuery builds a DNS standard query for the root NS record — a request
// almost any resolver answers.
func dnsRootQuery() []byte {
	return []byte{
		0x12, 0x34, // ID
		0x01, 0x00, // flags: recursion desired
		0x00, 0x01, // QDCOUNT = 1
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // AN/NS/AR = 0
		0x00,       // QNAME = root
		0x00, 0x02, // QTYPE = NS
		0x00, 0x01, // QCLASS = IN
	}
}

// ntpClientRequest builds a 48-byte NTPv3 client (mode 3) request.
func ntpClientRequest() []byte {
	b := make([]byte, 48)
	b[0] = 0x1b // LI=0, VN=3, Mode=3 (client)
	return b
}

// ssdpMSearch builds a unicast SSDP M-SEARCH discovery request.
func ssdpMSearch() []byte {
	return []byte("M-SEARCH * HTTP/1.1\r\n" +
		"HOST: 239.255.255.250:1900\r\n" +
		"MAN: \"ssdp:discover\"\r\n" +
		"MX: 1\r\n" +
		"ST: ssdp:all\r\n\r\n")
}

// mdnsServicesQuery builds an mDNS PTR query for _services._dns-sd._udp.local,
// the standard service-enumeration question.
func mdnsServicesQuery() []byte {
	out := []byte{
		0x00, 0x00, // ID
		0x00, 0x00, // flags
		0x00, 0x01, // QDCOUNT = 1
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // AN/NS/AR = 0
	}
	for _, label := range []string{"_services", "_dns-sd", "_udp", "local"} {
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	out = append(out, 0x00)       // end of QNAME
	out = append(out, 0x00, 0x0c) // QTYPE = PTR
	out = append(out, 0x00, 0x01) // QCLASS = IN
	return out
}
