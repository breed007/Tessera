package active

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// tcpResult is the outcome of a single TCP connect probe.
type tcpResult struct {
	open    bool   // the connection established → port is listening
	refused bool   // RST received → host is alive but the port is closed
	banner  string // optional, sanitized, single-line service banner
}

// alive reports whether the probe proves the host is up (open or refused both do;
// a timeout proves nothing — the host may be down or filtered).
func (r tcpResult) alive() bool { return r.open || r.refused }

// httpPorts are the plaintext-HTTP ports where a HEAD request elicits a useful
// Server banner. TLS ports are deliberately excluded (a plaintext read won't
// complete a TLS handshake) — those still yield open_port, just no banner.
var httpPorts = map[int]bool{80: true, 8080: true, 8000: true, 8008: true, 81: true}

// probeTCP performs a CONNECT-only probe (§4.2 / §8: no raw or SYN sockets). On
// connect it optionally grabs a light banner: a HEAD request for plaintext HTTP
// ports, otherwise whatever the server volunteers on connect (SSH/SMTP/etc).
// localIP, when valid, pins the connection's source address to the management
// interface so probes never egress a capture NIC.
func probeTCP(ctx context.Context, ip string, port int, connectTimeout, bannerTimeout time.Duration, localIP netip.Addr) tcpResult {
	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	d := net.Dialer{Timeout: connectTimeout}
	if localIP.IsValid() {
		d.LocalAddr = &net.TCPAddr{IP: localIP.AsSlice()}
	}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return tcpResult{refused: errors.Is(err, syscall.ECONNREFUSED)}
	}
	defer conn.Close()

	res := tcpResult{open: true}
	if bannerTimeout > 0 {
		res.banner = grabBanner(conn, port, bannerTimeout)
	}
	return res
}

// grabBanner reads a short, sanitized banner. Best-effort: any read error or
// timeout simply yields no banner.
func grabBanner(conn net.Conn, port int, timeout time.Duration) string {
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if httpPorts[port] {
		// A minimal HEAD request; we only want the response's first lines.
		_, _ = conn.Write([]byte("HEAD / HTTP/1.0\r\nHost: tessera.local\r\n\r\n"))
	}
	buf := make([]byte, 512)
	n, _ := conn.Read(buf)
	if n <= 0 {
		return ""
	}
	return sanitizeBanner(buf[:n])
}

// sanitizeBanner extracts the first non-empty line, keeps only printable ASCII,
// and caps the length so a hostile or chatty service can't bloat the log.
func sanitizeBanner(b []byte) string {
	line := b
	if i := indexNL(b); i >= 0 {
		line = b[:i]
	}
	var sb strings.Builder
	for _, c := range line {
		if c >= 0x20 && c <= 0x7e {
			sb.WriteByte(c)
		}
		if sb.Len() >= 200 {
			break
		}
	}
	return strings.TrimSpace(sb.String())
}

func indexNL(b []byte) int {
	for i, c := range b {
		if c == '\r' || c == '\n' {
			return i
		}
	}
	return -1
}
