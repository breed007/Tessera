package active

import (
	"context"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// icmpPinger sends ICMP echo requests to confirm liveness (§4.2). It uses an
// UNPRIVILEGED datagram-ICMP socket ("udp4"), which works without root on macOS
// and on Linux where net.ipv4.ping_group_range permits it. If the socket can't
// open (locked-down container, missing capability), newICMPPinger returns an
// error and the prober simply runs without ICMP — TCP-connect still provides
// liveness, so the prober degrades gracefully rather than failing.
type icmpPinger struct {
	conn *icmp.PacketConn
	id   int
	mu   sync.Mutex
	seq  int
}

// newICMPPinger opens the echo socket. sourceIP, when valid, binds it to the
// management interface so echo requests never originate from a capture NIC.
func newICMPPinger(sourceIP netip.Addr) (*icmpPinger, error) {
	listenAddr := "0.0.0.0"
	if sourceIP.IsValid() {
		listenAddr = sourceIP.String()
	}
	conn, err := icmp.ListenPacket("udp4", listenAddr)
	if err != nil {
		return nil, err
	}
	return &icmpPinger{conn: conn, id: os.Getpid() & 0xffff}, nil
}

// ping sends one echo request and waits up to timeout for the matching reply.
func (p *icmpPinger) ping(ctx context.Context, ip netip.Addr, timeout time.Duration) (bool, error) {
	p.mu.Lock()
	p.seq = (p.seq + 1) & 0xffff
	seq := p.seq
	p.mu.Unlock()

	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Body: &icmp.Echo{ID: p.id, Seq: seq, Data: []byte("tessera")},
	}
	wb, err := msg.Marshal(nil)
	if err != nil {
		return false, err
	}

	deadline := time.Now().Add(timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = p.conn.SetDeadline(deadline)

	dst := &net.UDPAddr{IP: net.IP(ip.AsSlice())}
	if _, err := p.conn.WriteTo(wb, dst); err != nil {
		return false, err
	}

	rb := make([]byte, 1500)
	for {
		n, peer, err := p.conn.ReadFrom(rb)
		if err != nil {
			return false, nil // timeout or transient → treat as no reply (not a fact)
		}
		rm, err := icmp.ParseMessage(1, rb[:n]) // 1 = IPv4 ICMP protocol number
		if err != nil {
			continue
		}
		if rm.Type != ipv4.ICMPTypeEchoReply {
			continue
		}
		if echo, ok := rm.Body.(*icmp.Echo); ok && echo.ID == p.id && echo.Seq == seq {
			if matchesPeer(peer, ip) {
				return true, nil
			}
		}
	}
}

func (p *icmpPinger) Close() {
	if p.conn != nil {
		_ = p.conn.Close()
	}
}

func matchesPeer(peer net.Addr, want netip.Addr) bool {
	switch a := peer.(type) {
	case *net.UDPAddr:
		ip, ok := netip.AddrFromSlice(a.IP)
		return ok && ip.Unmap() == want
	case *net.IPAddr:
		ip, ok := netip.AddrFromSlice(a.IP)
		return ok && ip.Unmap() == want
	}
	return false
}
