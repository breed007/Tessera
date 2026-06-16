// Package passive is the passive capture sensor (§4.1): it observes traffic on
// one or more capture sources (a normal interface in its own broadcast domain,
// or a NIC cabled to a SPAN/mirror/TAP for cross-VLAN visibility), parses the
// discovery protocols, and emits observations. It has ZERO network footprint —
// it only listens.
//
// The PARSERS in this file are pure (gopacket/layers decoding only, no libpcap)
// so they are fully unit-testable against crafted/captured frames. Live capture
// (which needs libpcap/cgo) is isolated behind a build tag in capture_pcap.go.
package passive

import (
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/tessera/tessera/internal/observation"
)

// emit is one observation produced by parsing. Each carries its own source
// (passive_arp, passive_dhcp, …) since a single frame's protocol determines it.
type emit struct {
	source      observation.Source
	subjectType observation.SubjectType
	subject     string
	attr        observation.Attribute
	value       string
	confidence  int
}

// Confidence levels. ARP/NDP are ground-truth L2 bindings; DHCP is strong;
// mDNS/SSDP/NetBIOS are softer hints. The reconciler's weighting does the rest.
const (
	confARPBinding  = 98
	confARPLiveness = 95
	confNDPBinding  = 95
	confDHCPBinding = 95
	confDHCPHost    = 85
	confDHCPFinger  = 90
	confDHCPVendor  = 85
	confMDNSHost    = 75
	confMDNSBinding = 70
	confMDNSClass   = 55 // device class from an advertised service type (_airplay, _printer, …)
	confMDNSOS      = 50 // OS inferred from a service type
	confMDNSModel   = 70 // device/OS from a TXT model= record (precise, device-reported)
	confNBNSHost    = 70
	confNBNSBinding = 65
	confSSDPClass   = 50
	confSSDPOS      = 45
	confSSDPBinding = 60
)

// Protocols selects which passive parsers are active. A protocol whose flag is
// false is never decoded — the corresponding discovery technique is off. The
// zero value enables nothing; AllProtocols enables everything (the default).
type Protocols struct {
	ARP     bool // ARP + IPv6 NDP
	DHCP    bool // DHCPv4 + DHCPv6
	MDNS    bool
	SSDP    bool
	NetBIOS bool
}

// AllProtocols enables every passive parser (the discovery default).
func AllProtocols() Protocols {
	return Protocols{ARP: true, DHCP: true, MDNS: true, SSDP: true, NetBIOS: true}
}

// parsePacket decodes one raw Ethernet frame and returns the observations it
// supports, honouring the enabled-protocol set. It never panics on malformed
// input — every layer is optional and missing/short layers simply yield fewer
// observations (SPAN is lossy; absence is never treated as a fact, §4.1).
func parsePacket(data []byte, ts time.Time, p Protocols) []emit {
	pkt := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.DecodeOptions{Lazy: true, NoCopy: true})

	eth, _ := pkt.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
	if eth == nil {
		return nil
	}
	srcMAC := eth.SrcMAC.String()

	// ARP — ground-truth MAC↔IP (no IP layer involved).
	if arp, ok := pkt.Layer(layers.LayerTypeARP).(*layers.ARP); ok {
		if !p.ARP {
			return nil
		}
		return handleARP(arp, ts)
	}

	// Source IP (for binding context in the L3 discovery protocols).
	srcIP := ""
	if ip4, ok := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4); ok {
		srcIP = ip4.SrcIP.String()
	} else if ip6, ok := pkt.Layer(layers.LayerTypeIPv6).(*layers.IPv6); ok {
		srcIP = ip6.SrcIP.String()
	}

	// NDP neighbour advertisement — IPv6 ground-truth binding (counts as ARP).
	if na, ok := pkt.Layer(layers.LayerTypeICMPv6NeighborAdvertisement).(*layers.ICMPv6NeighborAdvertisement); ok {
		if !p.ARP {
			return nil
		}
		if tgt := na.TargetAddress.String(); tgt != "" && srcMAC != "" {
			return []emit{{observation.SourcePassiveARP, observation.SubjectMAC, srcMAC, observation.AttrIPBinding, tgt, confNDPBinding}}
		}
	}

	udp, _ := pkt.Layer(layers.LayerTypeUDP).(*layers.UDP)
	if udp == nil {
		return nil
	}
	sp, dp := uint16(udp.SrcPort), uint16(udp.DstPort)

	switch {
	case sp == 67 || dp == 67 || sp == 68 || dp == 68:
		if !p.DHCP {
			return nil
		}
		return handleDHCPv4(udp.Payload, ts)
	case sp == 546 || dp == 546 || sp == 547 || dp == 547:
		if !p.DHCP {
			return nil
		}
		return handleDHCPv6(udp.Payload, srcMAC, ts)
	case sp == 5353 || dp == 5353:
		if !p.MDNS {
			return nil
		}
		return handleMDNS(udp.Payload, srcMAC, srcIP, ts)
	case sp == 1900 || dp == 1900:
		if !p.SSDP {
			return nil
		}
		return handleSSDP(udp.Payload, srcMAC, srcIP, ts)
	case sp == 137 || dp == 137:
		if !p.NetBIOS {
			return nil
		}
		return handleNBNS(udp.Payload, srcMAC, srcIP, ts)
	}
	return nil
}

func handleARP(arp *layers.ARP, ts time.Time) []emit {
	if len(arp.SourceHwAddress) != 6 || len(arp.SourceProtAddress) != 4 {
		return nil
	}
	mac := net.HardwareAddr(arp.SourceHwAddress).String()
	ip := net.IP(arp.SourceProtAddress).String()
	if ip == "0.0.0.0" { // ARP probe (announcing/duplicate-detection) — no binding
		return []emit{{observation.SourcePassiveARP, observation.SubjectMAC, mac, observation.AttrLiveness, "up", confARPLiveness}}
	}
	return []emit{
		{observation.SourcePassiveARP, observation.SubjectMAC, mac, observation.AttrIPBinding, ip, confARPBinding},
		{observation.SourcePassiveARP, observation.SubjectMAC, mac, observation.AttrLiveness, "up", confARPLiveness},
	}
}

func handleDHCPv4(payload []byte, ts time.Time) []emit {
	var d layers.DHCPv4
	if err := d.DecodeFromBytes(payload, gopacket.NilDecodeFeedback); err != nil {
		return nil
	}
	if len(d.ClientHWAddr) != 6 {
		return nil
	}
	mac := d.ClientHWAddr.String()
	var out []emit
	var msgType layers.DHCPMsgType
	for _, opt := range d.Options {
		switch opt.Type {
		case layers.DHCPOptHostname:
			if name := strings.TrimSpace(string(opt.Data)); name != "" {
				out = append(out, emit{observation.SourcePassiveDHCP, observation.SubjectMAC, mac, observation.AttrHostname, name, confDHCPHost})
			}
		case layers.DHCPOptClassID:
			if v := strings.TrimSpace(string(opt.Data)); v != "" {
				out = append(out, emit{observation.SourcePassiveDHCP, observation.SubjectMAC, mac, observation.AttrDHCPVendor, v, confDHCPVendor})
			}
		case layers.DHCPOptParamsRequest:
			// The Fingerbank DHCP fingerprint: the parameter-request-list option
			// numbers, in order, comma-joined (e.g. "1,3,6,15,28,51,58,59").
			if fp := joinBytes(opt.Data); fp != "" {
				out = append(out, emit{observation.SourcePassiveDHCP, observation.SubjectMAC, mac, observation.AttrDHCPFingerprint, fp, confDHCPFinger})
			}
		case layers.DHCPOptMessageType:
			if len(opt.Data) == 1 {
				msgType = layers.DHCPMsgType(opt.Data[0])
			}
		}
	}
	// A DHCP ACK carries the assigned address (yiaddr) → MAC↔IP binding.
	if msgType == layers.DHCPMsgTypeAck && d.YourClientIP != nil && !d.YourClientIP.IsUnspecified() {
		out = append(out, emit{observation.SourcePassiveDHCP, observation.SubjectMAC, mac, observation.AttrIPBinding, d.YourClientIP.String(), confDHCPBinding})
	}
	return out
}

// handleDHCPv6 extracts a hostname from the Client FQDN option, if present. The
// device is keyed by its source MAC (DHCPv6 has no chaddr).
func handleDHCPv6(payload []byte, srcMAC string, ts time.Time) []emit {
	var d layers.DHCPv6
	if err := d.DecodeFromBytes(payload, gopacket.NilDecodeFeedback); err != nil || srcMAC == "" {
		return nil
	}
	for _, opt := range d.Options {
		if opt.Code == layers.DHCPv6OptClientFQDN && len(opt.Data) > 1 {
			// First byte is flags; the rest is the FQDN (label-encoded or plain).
			if name := decodeFQDN(opt.Data[1:]); name != "" {
				return []emit{{observation.SourcePassiveDHCP6, observation.SubjectMAC, srcMAC, observation.AttrHostname, name, confDHCPHost}}
			}
		}
	}
	return nil
}

// handleMDNS extracts advertised hostnames + A/AAAA bindings, the advertised
// service types (_airplay, _googlecast, _printer, … → device class / OS), and a
// TXT model= record (the device's self-reported model → precise class / OS) from
// an mDNS response. The advertiser is keyed by its source MAC. Records can live
// in Answers OR Additionals (mDNS spreads SRV/TXT/PTR across both), so both are
// scanned.
func handleMDNS(payload []byte, srcMAC, srcIP string, ts time.Time) []emit {
	var dns layers.DNS
	if err := dns.DecodeFromBytes(payload, gopacket.NilDecodeFeedback); err != nil || srcMAC == "" {
		return nil
	}
	var out []emit
	seenHost := map[string]bool{}
	addHost := func(name string) {
		name = trimLocal(name)
		if name == "" || seenHost[name] {
			return
		}
		seenHost[name] = true
		out = append(out, emit{observation.SourcePassiveMDNS, observation.SubjectMAC, srcMAC, observation.AttrHostname, name, confMDNSHost})
	}
	seenClass := map[string]bool{}
	addClass := func(dev string, conf int) {
		if dev == "" || seenClass[dev] {
			return
		}
		seenClass[dev] = true
		out = append(out, emit{observation.SourcePassiveMDNS, observation.SubjectMAC, srcMAC, observation.AttrDeviceClass, dev, conf})
	}
	seenOS := map[string]bool{}
	addOS := func(os string, conf int) {
		if os == "" || seenOS[os] {
			return
		}
		seenOS[os] = true
		out = append(out, emit{observation.SourcePassiveMDNS, observation.SubjectMAC, srcMAC, observation.AttrOSGuess, os, conf})
	}

	records := append(append([]layers.DNSResourceRecord{}, dns.Answers...), dns.Additionals...)
	for _, rr := range records {
		switch rr.Type {
		case layers.DNSTypeA, layers.DNSTypeAAAA:
			addHost(string(rr.Name))
			if rr.IP != nil {
				out = append(out, emit{observation.SourcePassiveMDNS, observation.SubjectMAC, srcMAC, observation.AttrIPBinding, rr.IP.String(), confMDNSBinding})
			}
		case layers.DNSTypeSRV:
			addHost(string(rr.Name))
			if dev, os := classifyMDNSService(mdnsService(string(rr.Name))); dev != "" || os != "" {
				addClass(dev, confMDNSClass)
				addOS(os, confMDNSOS)
			}
		case layers.DNSTypePTR:
			// The service type is in the PTR record name (e.g. "_airplay._tcp.local").
			if dev, os := classifyMDNSService(mdnsService(string(rr.Name))); dev != "" || os != "" {
				addClass(dev, confMDNSClass)
				addOS(os, confMDNSOS)
			}
		case layers.DNSTypeTXT:
			// _device-info._tcp and friends carry a model= the device reports itself.
			if dev, os := classifyMDNSModel(txtValue(rr.TXTs, "model")); dev != "" || os != "" {
				addClass(dev, confMDNSModel)
				addOS(os, confMDNSModel)
			}
		}
	}
	if srcIP != "" {
		out = append(out, emit{observation.SourcePassiveMDNS, observation.SubjectMAC, srcMAC, observation.AttrIPBinding, srcIP, confMDNSBinding})
	}
	return out
}

// mdnsService extracts the application-protocol label from a DNS-SD name, i.e.
// the "_app" label immediately before "_tcp"/"_udp": "Lounge._airplay._tcp.local"
// → "_airplay". Returns "" if the name isn't a DNS-SD service name.
func mdnsService(name string) string {
	labels := strings.Split(strings.ToLower(strings.TrimSuffix(name, ".")), ".")
	for i, l := range labels {
		if (l == "_tcp" || l == "_udp") && i > 0 {
			prev := labels[i-1]
			if strings.HasPrefix(prev, "_") && prev != "_sub" {
				return prev
			}
		}
	}
	return ""
}

// classifyMDNSService maps a DNS-SD service type to a device class and (rarely) an
// OS. Service advertisement is a strong, deterministic device hint.
func classifyMDNSService(svc string) (dev, os string) {
	switch svc {
	case "_airplay", "_googlecast", "_nvstream", "_amzn-wplay", "_androidtvremote2", "_dial", "_roku-rcp":
		return "media / TV device", ""
	case "_raop", "_spotify-connect", "_sonos":
		return "speaker", ""
	case "_printer", "_ipp", "_ipps", "_pdl-datastream", "_scanner", "_uscan", "_uscans":
		return "printer", ""
	case "_smb", "_afpovertcp", "_adisk", "_nfs", "_ftp":
		return "NAS", ""
	case "_homekit", "_hap", "_hue", "_matter", "_matterc":
		return "IoT device", ""
	case "_apple-mobdev2":
		return "Apple mobile device", "iOS"
	}
	return "", ""
}

// classifyMDNSModel maps a TXT model= value (the device's self-reported model,
// e.g. "AppleTV6,2", "Macmini8,1", "iPhone14,2", "AudioAccessory5,1") to a class
// and OS. Cryptic board ids (e.g. "J305AP") are left unclassified rather than
// guessed.
func classifyMDNSModel(model string) (dev, os string) {
	m := strings.ToLower(model)
	switch {
	case m == "":
		return "", ""
	case strings.HasPrefix(m, "appletv"):
		return "media / TV device", "tvOS"
	case strings.HasPrefix(m, "audioaccessory"):
		return "speaker", ""
	case strings.HasPrefix(m, "iphone"), strings.HasPrefix(m, "ipad"), strings.HasPrefix(m, "ipod"):
		return "Apple mobile device", "iOS"
	case strings.HasPrefix(m, "watch"):
		return "smartwatch", "watchOS"
	case strings.HasPrefix(m, "macbook"), strings.HasPrefix(m, "imac"), strings.HasPrefix(m, "macmini"),
		strings.HasPrefix(m, "macpro"), strings.HasPrefix(m, "macstudio"), strings.HasPrefix(m, "mac"):
		return "computer", "macOS"
	}
	return "", ""
}

// txtValue returns the value of key (case-insensitive) from a set of DNS TXT
// "key=value" records, or "".
func txtValue(txts [][]byte, key string) string {
	key = strings.ToLower(key)
	for _, t := range txts {
		k, v, ok := strings.Cut(string(t), "=")
		if ok && strings.ToLower(strings.TrimSpace(k)) == key {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// handleSSDP parses an SSDP (UPnP) NOTIFY/M-SEARCH response: the SERVER header
// gives a soft OS hint, the NT/ST URN gives a soft device class.
func handleSSDP(payload []byte, srcMAC, srcIP string, ts time.Time) []emit {
	if srcMAC == "" {
		return nil
	}
	var out []emit
	for _, line := range strings.Split(string(payload), "\n") {
		k, v, ok := splitHeader(line)
		if !ok {
			continue
		}
		switch k {
		case "server":
			if os := firstToken(v); os != "" {
				out = append(out, emit{observation.SourcePassiveSSDP, observation.SubjectMAC, srcMAC, observation.AttrOSGuess, os, confSSDPOS})
			}
		case "nt", "st":
			if dev := urnDeviceToken(v); dev != "" {
				out = append(out, emit{observation.SourcePassiveSSDP, observation.SubjectMAC, srcMAC, observation.AttrDeviceClass, dev, confSSDPClass})
			}
		}
	}
	if len(out) > 0 && srcIP != "" {
		out = append(out, emit{observation.SourcePassiveSSDP, observation.SubjectMAC, srcMAC, observation.AttrIPBinding, srcIP, confSSDPBinding})
	}
	return out
}

// handleNBNS decodes the queried NetBIOS name from a NetBIOS-NS packet.
func handleNBNS(payload []byte, srcMAC, srcIP string, ts time.Time) []emit {
	if srcMAC == "" {
		return nil
	}
	name := decodeNetBIOSName(payload)
	if name == "" {
		return nil
	}
	out := []emit{{observation.SourcePassiveNBNS, observation.SubjectMAC, srcMAC, observation.AttrHostname, name, confNBNSHost}}
	if srcIP != "" {
		out = append(out, emit{observation.SourcePassiveNBNS, observation.SubjectMAC, srcMAC, observation.AttrIPBinding, srcIP, confNBNSBinding})
	}
	return out
}

// ── parsing helpers ──────────────────────────────────────────────────────────

// joinBytes renders a byte slice as comma-joined decimal numbers (the DHCP
// fingerprint encoding).
func joinBytes(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	parts := make([]string, len(b))
	for i, v := range b {
		parts[i] = strconv.Itoa(int(v))
	}
	return strings.Join(parts, ",")
}

// trimLocal strips a trailing mDNS ".local" (and any trailing dot).
func trimLocal(name string) string {
	name = strings.TrimSuffix(strings.TrimSpace(name), ".")
	name = strings.TrimSuffix(name, ".local")
	return strings.TrimSpace(name)
}

func splitHeader(line string) (key, val string, ok bool) {
	i := strings.IndexByte(line, ':')
	if i < 0 {
		return "", "", false
	}
	return strings.ToLower(strings.TrimSpace(line[:i])), strings.TrimSpace(line[i+1:]), true
}

func firstToken(s string) string {
	for _, f := range strings.Fields(s) {
		return f
	}
	return ""
}

// urnDeviceToken pulls the device type from a UPnP URN, e.g.
// "urn:schemas-upnp-org:device:MediaServer:1" → "MediaServer".
func urnDeviceToken(s string) string {
	parts := strings.Split(s, ":")
	for i := 0; i+1 < len(parts); i++ {
		if parts[i] == "device" {
			return parts[i+1]
		}
	}
	return ""
}

// decodeFQDN turns a DNS label-encoded (or already plain) FQDN into a dotted
// hostname, returning the first label as the host name.
func decodeFQDN(b []byte) string {
	// Plain text form (no length-prefixed labels): printable with dots.
	if isPrintable(b) && strings.ContainsAny(string(b), ".") {
		return trimLocal(strings.SplitN(string(b), ".", 2)[0])
	}
	// Label-encoded: <len><label><len><label>...<0>
	var labels []string
	for i := 0; i < len(b); {
		n := int(b[i])
		if n == 0 || i+1+n > len(b) {
			break
		}
		labels = append(labels, string(b[i+1:i+1+n]))
		i += 1 + n
	}
	if len(labels) == 0 {
		return ""
	}
	return trimLocal(labels[0])
}

// decodeNetBIOSName decodes the first-level-encoded NetBIOS name from a
// NetBIOS-NS packet (12-byte header, then a 0x20-length 32-byte encoded name).
func decodeNetBIOSName(payload []byte) string {
	const hdr = 12
	if len(payload) < hdr+1+32 {
		return ""
	}
	if payload[hdr] != 0x20 {
		return ""
	}
	enc := payload[hdr+1 : hdr+1+32]
	var name strings.Builder
	for i := 0; i+1 < len(enc); i += 2 {
		hi, lo := enc[i], enc[i+1]
		if hi < 'A' || hi > 'P' || lo < 'A' || lo > 'P' {
			return ""
		}
		name.WriteByte(((hi - 'A') << 4) | (lo - 'A'))
	}
	// The 16th byte is the service suffix; the name is the first 15, space-padded.
	s := name.String()
	if len(s) >= 16 {
		s = s[:15]
	}
	return strings.TrimSpace(s)
}

func isPrintable(b []byte) bool {
	for _, c := range b {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return len(b) > 0
}
