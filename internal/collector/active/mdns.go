package active

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/tessera/tessera/internal/collector/passive"
)

// mDNS service-type catalog — ported from the IP Recon MDNSActiveStimulus list.
// Each is a DNS-SD PTR question; a device that speaks the service answers with a
// PTR (and usually SRV/TXT/A), which reveals its class, model, and name. This is
// how Fire TV / Apple TV / Chromecast / Ring / Echo etc. announce themselves —
// and it works SPAN-free because we query each host's :5353 directly (unicast).
var mdnsServiceCatalog = []string{
	"_services._dns-sd._udp.local.", // meta-query: lists every service on the host

	// Apple OS/hardware identification (carry model= / osxvers= in TXT).
	"_device-info._tcp.local.",
	"_companion-link._tcp.local.",
	"_appletv-v2._tcp.local.",
	"_airplay._tcp.local.",
	"_raop._tcp.local.",
	"_mediaremotetv._tcp.local.",
	"_apple-mobdev2._tcp.local.",

	// Streaming / TV / speakers.
	"_googlecast._tcp.local.", // Chromecast, Nest displays, Android TV
	"_spotify-connect._tcp.local.",
	"_sonos._tcp.local.",
	"_androidtvremote2._tcp.local.",
	"_dial._tcp.local.",
	"_roku-rcp._tcp.local.",
	"_nvstream._tcp.local.", // NVIDIA Shield / GameStream

	// Amazon (Echo, Fire TV, Kindle, Ring).
	"_amzn-alexa._tcp.local.",
	"_amazonfire._tcp.local.",
	"_amzn-wplay._tcp.local.", // Fire TV / Kindle Fire
	"_ring._tcp.local.",

	// Smart-home / IoT.
	"_homekit._tcp.local.",
	"_hap._tcp.local.",
	"_hue._tcp.local.",
	"_matter._tcp.local.",
	"_matterc._udp.local.",
	"_esphomelib._tcp.local.",

	// Computers / NAS / printers.
	"_workstation._tcp.local.",
	"_smb._tcp.local.",
	"_afpovertcp._tcp.local.",
	"_ipp._tcp.local.",
	"_printer._tcp.local.",
	"_scanner._tcp.local.",
}

// mdnsFindings is what an active mDNS query surfaced about one host.
type mdnsFindings struct {
	services []string // service labels seen, e.g. "_airplay"
	model    string   // TXT model= self-report (e.g. "AppleTV14,1", "Mac16,7")
	name     string   // instance / host name
}

// hasService reports whether any of the given service labels (e.g. "_airplay")
// were advertised — used to gate the follow-up media HTTP probes.
func (f *mdnsFindings) hasService(labels ...string) bool {
	for _, s := range f.services {
		for _, want := range labels {
			if s == want {
				return true
			}
		}
	}
	return false
}

// queryMDNS sends one unicast mDNS query (all catalog questions, QU bit set) to
// ip:5353 and parses whatever answers arrive within the timeout. Returns nil when
// nothing usable came back. localIP, when valid, pins the source to the mgmt NIC.
func queryMDNS(ctx context.Context, ip string, timeout time.Duration, localIP netip.Addr) *mdnsFindings {
	pkt, err := buildMDNSQuery(mdnsServiceCatalog)
	if err != nil {
		return nil
	}
	d := net.Dialer{Timeout: 2 * time.Second}
	if localIP.IsValid() {
		d.LocalAddr = &net.UDPAddr{IP: localIP.AsSlice()}
	}
	conn, err := d.DialContext(ctx, "udp", net.JoinHostPort(ip, "5353"))
	if err != nil {
		return nil
	}
	defer conn.Close()
	if _, err := conn.Write(pkt); err != nil {
		return nil
	}

	f := &mdnsFindings{}
	svcSet := map[string]bool{}
	deadline := time.Now().Add(timeout)
	_ = conn.SetReadDeadline(deadline)
	buf := make([]byte, 4096)
	// A host may answer with several datagrams; read until the timeout.
	for time.Now().Before(deadline) {
		n, err := conn.Read(buf)
		if err != nil {
			break
		}
		parseMDNSResponse(buf[:n], f, svcSet)
	}
	for s := range svcSet {
		f.services = append(f.services, s)
	}
	if len(f.services) == 0 && f.model == "" && f.name == "" {
		return nil
	}
	return f
}

// buildMDNSQuery encodes a single mDNS query message carrying one PTR question
// per service type, each with the unicast-response (QU) bit set so responders
// reply directly to us instead of multicasting.
func buildMDNSQuery(services []string) ([]byte, error) {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{})
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	const quIN = dnsmessage.Class(0x8001) // top bit = unicast response, | IN(1)
	for _, s := range services {
		name, err := dnsmessage.NewName(s)
		if err != nil {
			continue
		}
		if err := b.Question(dnsmessage.Question{Name: name, Type: dnsmessage.TypePTR, Class: quIN}); err != nil {
			return nil, err
		}
	}
	return b.Finish()
}

// parseMDNSResponse folds one response datagram into f: PTR/SRV names → service
// labels + instance name, TXT model= → model, A/AAAA owner → name fallback.
func parseMDNSResponse(data []byte, f *mdnsFindings, svcSet map[string]bool) {
	var p dnsmessage.Parser
	if _, err := p.Start(data); err != nil {
		return
	}
	_ = p.SkipAllQuestions()
	// Walk answers + additionals (SRV/TXT usually ride in Additionals).
	for _, section := range []func() (dnsmessage.Resource, error){nextAnswer(&p), nextAuthority(&p), nextAdditional(&p)} {
		for {
			r, err := section()
			if err != nil {
				break
			}
			foldMDNSResource(r, f, svcSet)
		}
	}
}

func foldMDNSResource(r dnsmessage.Resource, f *mdnsFindings, svcSet map[string]bool) {
	owner := strings.TrimSuffix(r.Header.Name.String(), ".")
	if svc := passive.MDNSServiceLabel(owner); svc != "" {
		svcSet[svc] = true
	}
	switch body := r.Body.(type) {
	case *dnsmessage.PTRResource:
		target := strings.TrimSuffix(body.PTR.String(), ".")
		if svc := passive.MDNSServiceLabel(target); svc != "" {
			svcSet[svc] = true
		}
		if inst := instanceName(target); inst != "" && f.name == "" {
			f.name = inst
		}
	case *dnsmessage.SRVResource:
		if inst := instanceName(owner); inst != "" && f.name == "" {
			f.name = inst
		}
	case *dnsmessage.TXTResource:
		for _, kv := range body.TXT {
			if v, ok := strings.CutPrefix(kv, "model="); ok && f.model == "" {
				f.model = strings.TrimSpace(v)
			}
		}
	case *dnsmessage.AResource, *dnsmessage.AAAAResource:
		if h := hostLabel(owner); h != "" && f.name == "" {
			f.name = h
		}
	}
}

// instanceName pulls the human instance label from a DNS-SD name, e.g.
// "Living Room._airplay._tcp.local" → "Living Room". Empty if it isn't one.
func instanceName(name string) string {
	labels := strings.Split(strings.TrimSuffix(name, "."), ".")
	for i, l := range labels {
		if (l == "_tcp" || l == "_udp") && i >= 1 {
			// The instance is everything before the "_service" label.
			if i >= 2 {
				return strings.Join(labels[:i-1], ".")
			}
			return ""
		}
	}
	return ""
}

// hostLabel returns the first label of a plain hostname (e.g. "nas.local" → "nas"),
// skipping DNS-SD service names.
func hostLabel(name string) string {
	if strings.Contains(name, "._tcp") || strings.Contains(name, "._udp") {
		return ""
	}
	first, _, _ := strings.Cut(strings.TrimSuffix(name, ".local"), ".")
	if strings.EqualFold(first, "localhost") {
		return ""
	}
	return first
}

// dnsmessage's Parser exposes per-section iterators; these adapt them to a common
// "next resource or error" signature so the three sections share one fold loop.
func nextAnswer(p *dnsmessage.Parser) func() (dnsmessage.Resource, error) {
	return func() (dnsmessage.Resource, error) { return p.Answer() }
}
func nextAuthority(p *dnsmessage.Parser) func() (dnsmessage.Resource, error) {
	return func() (dnsmessage.Resource, error) { return p.Authority() }
}
func nextAdditional(p *dnsmessage.Parser) func() (dnsmessage.Resource, error) {
	return func() (dnsmessage.Resource, error) { return p.Additional() }
}
