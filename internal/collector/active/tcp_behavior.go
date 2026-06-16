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

// behaviorPorts are high, almost-never-listening ports. Probing one of them on
// an already-alive host reveals how its TCP stack / firewall treats unwanted
// connections — without touching a real service.
var behaviorPorts = []int{47802, 53901}

// Closed-port behaviour classes (the AttrTCPBehavior value). These are NOT
// classic p0f/nmap -O fingerprints — a userspace CONNECT can't see SYN-ACK
// options — so the signal is weak and only ever corroborates (confTCPBehavior).
const (
	behaviorRSTImmediate    = "rst_immediate"    // fast RST: a general-purpose OS with no firewall (Windows/macOS/Linux desktop, BSD)
	behaviorSilentDrop      = "silent_drop"      // connect times out: stateful firewall / hardened embedded device
	behaviorICMPUnreachable = "icmp_unreachable" // slow failure: ICMP admin-prohibited forwarded as a connect error
)

// probeTCPBehavior connects to a likely-closed port on an alive host and
// classifies the failure timing. Returns "" when the result is inconclusive
// (e.g. the "closed" port unexpectedly answered, or the probe couldn't run).
//
// Timing thresholds mirror IP Recon's TCPBehaviorProbe: a sub-100ms failure is
// an immediate RST; a failure that takes most of the connect timeout is a silent
// drop; in between is consistent with a forwarded ICMP unreachable.
func probeTCPBehavior(ctx context.Context, ip string, connectTimeout time.Duration, localIP netip.Addr, lim *limiter) string {
	for _, port := range behaviorPorts {
		if lim.wait(ctx) != nil {
			return ""
		}
		d := net.Dialer{Timeout: connectTimeout}
		if localIP.IsValid() {
			d.LocalAddr = &net.TCPAddr{IP: localIP.AsSlice()}
		}
		start := time.Now()
		conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
		elapsed := time.Since(start)
		if err == nil {
			// The port we assumed closed is actually open — uninformative; try the next.
			_ = conn.Close()
			continue
		}
		switch {
		case errors.Is(err, syscall.ECONNREFUSED):
			if elapsed < 100*time.Millisecond {
				return behaviorRSTImmediate
			}
			return behaviorICMPUnreachable
		case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
			return ""
		default:
			// A non-refused failure that consumed most of the timeout window is a
			// silent drop; a quicker one looks like an ICMP unreachable.
			if elapsed >= connectTimeout-(connectTimeout/4) {
				return behaviorSilentDrop
			}
			return behaviorICMPUnreachable
		}
	}
	return ""
}
