package active

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"
)

// TestProbeUDPOpen starts a UDP echo responder and confirms a reply marks the
// port open.
func TestProbeUDPOpen(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 1024)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(buf[:n], addr) // echo
		}
	}()

	port := pc.LocalAddr().(*net.UDPAddr).Port
	res := probeUDP(context.Background(), "127.0.0.1", port, time.Second, netip.Addr{})
	if !res.open {
		t.Fatalf("expected open, got %+v", res)
	}
	if !res.alive() {
		t.Fatal("open port must count as alive")
	}
}

// TestProbeUDPClosed probes a port with no listener. On most stacks the kernel
// returns an ICMP port-unreachable (→ refused); on some CI sandboxes it is
// swallowed (→ timeout). Both are acceptable — neither must report "open".
func TestProbeUDPClosed(t *testing.T) {
	res := probeUDP(context.Background(), "127.0.0.1", 9, 300*time.Millisecond, netip.Addr{})
	if res.open {
		t.Fatalf("closed port must not be reported open: %+v", res)
	}
}

// TestUDPPayloadsWellFormed sanity-checks the canned probe payloads.
func TestUDPPayloadsWellFormed(t *testing.T) {
	if len(ntpClientRequest()) != 48 {
		t.Error("NTP request must be 48 bytes")
	}
	if ntpClientRequest()[0] != 0x1b {
		t.Error("NTP first byte must be 0x1b (v3 client)")
	}
	// 12-byte header, then QNAME=0x00 (root), QTYPE=NS(0x0002), QCLASS=IN(0x0001).
	if got := dnsRootQuery(); len(got) != 17 || got[12] != 0x00 || got[14] != 0x02 || got[16] != 0x01 {
		t.Errorf("DNS root query malformed: %v", got)
	}
	for _, p := range []int{53, 123, 1900, 5353} {
		if len(udpPayloads[p]) == 0 {
			t.Errorf("missing payload for well-known UDP port %d", p)
		}
	}
}
