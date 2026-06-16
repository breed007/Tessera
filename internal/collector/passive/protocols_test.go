package passive

import (
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// arpFrame builds a minimal Ethernet+ARP reply for gating tests.
func arpFrame(t *testing.T) []byte {
	t.Helper()
	eth := &layers.Ethernet{
		SrcMAC:       []byte{0xaa, 0xbb, 0xcc, 0x11, 0x22, 0x33},
		DstMAC:       []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := &layers.ARP{
		AddrType: layers.LinkTypeEthernet, Protocol: layers.EthernetTypeIPv4,
		HwAddressSize: 6, ProtAddressSize: 4, Operation: layers.ARPReply,
		SourceHwAddress: []byte{0xaa, 0xbb, 0xcc, 0x11, 0x22, 0x33}, SourceProtAddress: []byte{10, 0, 0, 5},
		DstHwAddress: []byte{0, 0, 0, 0, 0, 0}, DstProtAddress: []byte{10, 0, 0, 1},
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true}, eth, arp); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestProtocolGating(t *testing.T) {
	frame := arpFrame(t)
	now := time.Now()

	if got := parsePacket(frame, now, AllProtocols()); len(got) == 0 {
		t.Fatal("ARP enabled: expected observations, got none")
	}
	// ARP disabled → no observations even though the frame is well-formed.
	if got := parsePacket(frame, now, Protocols{DHCP: true, MDNS: true}); len(got) != 0 {
		t.Fatalf("ARP disabled: expected no observations, got %d", len(got))
	}
	// Zero value enables nothing.
	if got := parsePacket(frame, now, Protocols{}); len(got) != 0 {
		t.Fatalf("zero Protocols: expected no observations, got %d", len(got))
	}
}
