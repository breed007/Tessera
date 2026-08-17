package passive

import (
	"net"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/breed007/Tessera/internal/observation"
)

var now = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

func findEmit(es []emit, attr observation.Attribute) *emit {
	for i := range es {
		if es[i].attr == attr {
			return &es[i]
		}
	}
	return nil
}

// buildUDPv4 serializes an Ethernet/IPv4/UDP frame carrying app, so parsePacket
// is exercised end-to-end including the port dispatch.
func buildUDPv4(t *testing.T, srcMAC, srcIP string, srcPort, dstPort int, app gopacket.SerializableLayer) []byte {
	t.Helper()
	mac, _ := net.ParseMAC(srcMAC)
	eth := &layers.Ethernet{SrcMAC: mac, DstMAC: net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: net.ParseIP(srcIP).To4(), DstIP: net.IPv4(255, 255, 255, 255)}
	udp := &layers.UDP{SrcPort: layers.UDPPort(srcPort), DstPort: layers.UDPPort(dstPort)}
	_ = udp.SetNetworkLayerForChecksum(ip)
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, udp, app); err != nil {
		t.Fatalf("serialize: %v", err)
	}
	return buf.Bytes()
}

func TestParseARP(t *testing.T) {
	mac, _ := net.ParseMAC("b8:27:eb:11:22:33")
	eth := &layers.Ethernet{SrcMAC: mac, DstMAC: net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, EthernetType: layers.EthernetTypeARP}
	arp := &layers.ARP{
		AddrType: layers.LinkTypeEthernet, Protocol: layers.EthernetTypeIPv4,
		HwAddressSize: 6, ProtAddressSize: 4, Operation: layers.ARPReply,
		SourceHwAddress: mac, SourceProtAddress: net.ParseIP("10.0.0.20").To4(),
		DstHwAddress: make([]byte, 6), DstProtAddress: make([]byte, 4),
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{}, eth, arp); err != nil {
		t.Fatal(err)
	}
	es := parsePacket(buf.Bytes(), now, AllProtocols())

	bind := findEmit(es, observation.AttrIPBinding)
	if bind == nil || bind.subject != "b8:27:eb:11:22:33" || bind.value != "10.0.0.20" || bind.source != observation.SourcePassiveARP {
		t.Fatalf("arp binding wrong: %+v", bind)
	}
	if findEmit(es, observation.AttrLiveness) == nil {
		t.Error("arp should yield liveness")
	}
}

func TestParseDHCPv4(t *testing.T) {
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:01")
	dhcp := &layers.DHCPv4{
		Operation: layers.DHCPOpReply, HardwareType: layers.LinkTypeEthernet, HardwareLen: 6,
		ClientHWAddr: mac, YourClientIP: net.ParseIP("10.0.0.50").To4(),
		Options: layers.DHCPOptions{
			layers.NewDHCPOption(layers.DHCPOptMessageType, []byte{byte(layers.DHCPMsgTypeAck)}),
			layers.NewDHCPOption(layers.DHCPOptHostname, []byte("laptop")),
			layers.NewDHCPOption(layers.DHCPOptClassID, []byte("MSFT 5.0")),
			layers.NewDHCPOption(layers.DHCPOptParamsRequest, []byte{1, 3, 6, 15, 31, 33}),
		},
	}
	frame := buildUDPv4(t, "aa:bb:cc:dd:ee:01", "0.0.0.0", 67, 68, dhcp)
	es := parsePacket(frame, now, AllProtocols())

	if e := findEmit(es, observation.AttrDHCPFingerprint); e == nil || e.value != "1,3,6,15,31,33" {
		t.Errorf("dhcp fingerprint wrong: %+v", e) // this is the key Fingerbank input
	}
	if e := findEmit(es, observation.AttrHostname); e == nil || e.value != "laptop" {
		t.Errorf("dhcp hostname wrong: %+v", e)
	}
	if e := findEmit(es, observation.AttrDHCPVendor); e == nil || e.value != "MSFT 5.0" {
		t.Errorf("dhcp vendor wrong: %+v", e)
	}
	if e := findEmit(es, observation.AttrIPBinding); e == nil || e.value != "10.0.0.50" || e.subject != "aa:bb:cc:dd:ee:01" {
		t.Errorf("dhcp ACK binding wrong: %+v", e)
	}
}

func TestParseMDNS(t *testing.T) {
	dns := &layers.DNS{
		QR: true,
		Answers: []layers.DNSResourceRecord{{
			Name: []byte("MacBook.local"), Type: layers.DNSTypeA, Class: layers.DNSClassIN,
			IP: net.ParseIP("10.0.0.42").To4(),
		}},
	}
	es := handleMDNS(serialize(t, dns), "aa:bb:cc:dd:ee:02", "10.0.0.42", now)
	if e := findEmit(es, observation.AttrHostname); e == nil || e.value != "MacBook" {
		t.Errorf("mdns hostname wrong (should strip .local): %+v", e)
	}
	if findEmit(es, observation.AttrIPBinding) == nil {
		t.Error("mdns A record should yield a binding")
	}
}

func TestParseMDNSServices(t *testing.T) {
	dns := &layers.DNS{
		QR: true,
		// PTR service advertisement in Answers; TXT model in Additionals.
		Answers: []layers.DNSResourceRecord{{
			Name: []byte("Den._airplay._tcp.local"), Type: layers.DNSTypePTR, Class: layers.DNSClassIN,
			PTR: []byte("Den._airplay._tcp.local"),
		}},
		Additionals: []layers.DNSResourceRecord{{
			Name: []byte("Den._device-info._tcp.local"), Type: layers.DNSTypeTXT, Class: layers.DNSClassIN,
			TXTs: [][]byte{[]byte("model=AppleTV6,2")},
		}},
	}
	es := handleMDNS(serialize(t, dns), "aa:bb:cc:00:00:14", "10.0.0.121", now)

	// The exact model name from the TXT record lands in model; the service type
	// still classifies the device.
	if e := findEmit(es, observation.AttrModel); e == nil || e.value != "Apple TV 4K (1st generation)" {
		t.Errorf("mdns exact model wrong: %+v", e)
	}
	if e := findEmit(es, observation.AttrDeviceClass); e == nil || e.value != "media / TV device" {
		t.Errorf("mdns service device_class wrong: %+v", e)
	}
	if e := findEmit(es, observation.AttrOSGuess); e == nil || e.value != "tvOS" {
		t.Errorf("mdns model os_guess wrong (want tvOS from model=AppleTV6,2): %+v", e)
	}
}

func TestParseMDNSAppleModelPrecise(t *testing.T) {
	// An M4 16" MacBook reports model=Mac16,7 via _device-info.
	dns := &layers.DNS{
		QR: true,
		Answers: []layers.DNSResourceRecord{{
			Name: []byte("studiombp14._device-info._tcp.local"), Type: layers.DNSTypeTXT, Class: layers.DNSClassIN,
			TXTs: [][]byte{[]byte("model=Mac16,7")},
		}},
	}
	es := handleMDNS(serialize(t, dns), "aa:bb:cc:dd:ee:10", "10.0.0.42", now)
	e := findEmit(es, observation.AttrModel)
	if e == nil || e.value != "MacBook Pro (16-inch, M4 Pro, Nov 2024)" {
		t.Fatalf("precise mac model wrong: %+v", e)
	}
	// Precise self-report must outrank a UniFi fingerprint (conf 75) so it wins.
	if e.confidence <= 75 {
		t.Errorf("precise mDNS model conf = %d, must exceed UniFi fingerprint (75)", e.confidence)
	}
	if e := findEmit(es, observation.AttrOSGuess); e == nil || e.value != "macOS" {
		t.Errorf("mac os_guess wrong: %+v", e)
	}
}

func TestMDNSServiceHelpers(t *testing.T) {
	if got := mdnsService("Lounge._googlecast._tcp.local"); got != "_googlecast" {
		t.Errorf("mdnsService = %q, want _googlecast", got)
	}
	if got := mdnsService("HP._printer._tcp.local."); got != "_printer" {
		t.Errorf("mdnsService = %q, want _printer", got)
	}
	if got := mdnsService("MacBook.local"); got != "" {
		t.Errorf("mdnsService on a plain host = %q, want empty", got)
	}
	if dev, _ := classifyMDNSService("_printer"); dev != "printer" {
		t.Errorf("_printer → %q, want printer", dev)
	}
	if dev, os, precise := classifyMDNSModel("Macmini8,1"); dev != "Mac mini (Late 2018)" || os != "macOS" || !precise {
		t.Errorf("Macmini8,1 → %q/%q/%v, want exact Mac mini (Late 2018)/macOS/true", dev, os, precise)
	}
	if dev, _, precise := classifyMDNSModel("Mac99,9"); dev != "computer" || precise {
		t.Errorf("unknown mac id → %q/%v, want coarse computer/false", dev, precise)
	}
	if got := txtValue([][]byte{[]byte("rpBA=AA"), []byte("model=J305AP")}, "model"); got != "J305AP" {
		t.Errorf("txtValue model = %q, want J305AP", got)
	}
}

func TestParseNBNS(t *testing.T) {
	payload := encodeNBNS("WORKSTATION", 0x00)
	es := handleNBNS(payload, "aa:bb:cc:dd:ee:03", "10.0.0.7", now)
	if e := findEmit(es, observation.AttrHostname); e == nil || e.value != "WORKSTATION" {
		t.Errorf("netbios name decode wrong: %+v", e)
	}
}

func TestParseSSDP(t *testing.T) {
	payload := []byte("NOTIFY * HTTP/1.1\r\n" +
		"SERVER: Linux/4.9 UPnP/1.0 MiniDLNA/1.2\r\n" +
		"NT: urn:schemas-upnp-org:device:MediaServer:1\r\n\r\n")
	es := handleSSDP(payload, "aa:bb:cc:dd:ee:04", "10.0.0.8", now)
	if e := findEmit(es, observation.AttrDeviceClass); e == nil || e.value != "MediaServer" {
		t.Errorf("ssdp device class wrong: %+v", e)
	}
	if e := findEmit(es, observation.AttrOSGuess); e == nil || e.value != "Linux/4.9" {
		t.Errorf("ssdp os guess wrong: %+v", e)
	}
}

func TestDedup(t *testing.T) {
	d := newDeduper(50 * time.Millisecond)
	frame := []byte("a-mirrored-frame")
	if d.duplicate(frame, now) {
		t.Error("first sighting should not be a duplicate")
	}
	if !d.duplicate(frame, now.Add(10*time.Millisecond)) {
		t.Error("second sighting within window should be a duplicate (SPAN ingress+egress)")
	}
	if d.duplicate(frame, now.Add(200*time.Millisecond)) {
		t.Error("sighting past the window should not be a duplicate")
	}
}

// ── test helpers ─────────────────────────────────────────────────────────────

func serialize(t *testing.T, l gopacket.SerializableLayer) []byte {
	t.Helper()
	buf := gopacket.NewSerializeBuffer()
	if err := l.SerializeTo(buf, gopacket.SerializeOptions{FixLengths: true}); err != nil {
		t.Fatalf("serialize: %v", err)
	}
	return buf.Bytes()
}

// encodeNBNS builds a minimal NetBIOS-NS packet whose question is name+suffix,
// using the first-level name encoding the parser decodes.
func encodeNBNS(name string, suffix byte) []byte {
	raw := make([]byte, 16)
	for i := 0; i < 15; i++ {
		if i < len(name) {
			raw[i] = name[i]
		} else {
			raw[i] = ' '
		}
	}
	raw[15] = suffix
	enc := make([]byte, 32)
	for i, b := range raw {
		enc[i*2] = 'A' + (b >> 4)
		enc[i*2+1] = 'A' + (b & 0x0f)
	}
	pkt := make([]byte, 0, 12+1+32+1)
	pkt = append(pkt, make([]byte, 12)...) // header
	pkt = append(pkt, 0x20)                // name length
	pkt = append(pkt, enc...)
	pkt = append(pkt, 0x00) // null terminator
	return pkt
}
