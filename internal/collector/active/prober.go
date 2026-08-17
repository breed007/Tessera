package active

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/breed007/Tessera/internal/collector/passive"
	"github.com/breed007/Tessera/internal/observation"
)

// Config configures the active prober. Subnets are mandatory and explicit
// (§4.2: never unscoped) — the caller (config validation) guarantees this. The
// technique flags (TCP/Banners/RDNS/ARPTable/SNMP/TCPBehavioral/ThoroughWake)
// come from the Discovery settings; they default ON when constructed via
// buildCollectors. A zero-value Config (used in tests) is normalised in
// NewProber so the classic ICMP+TCP+banner+rDNS+ARP sweep still runs.
type Config struct {
	Subnets         []string
	TCPPorts        []int
	UDPPorts        []int
	ICMP            bool
	TCP             bool
	UDP             bool // scan the listed UDP ports
	Banners         bool
	ReverseDNS      bool
	ARPTable        bool
	SNMP            bool     // gate SNMP independently of the community being set
	SNMPCommunities []string // tried in order; empty → SNMP disabled
	MDNS            bool     // unicast mDNS query for service types / model=
	Media           bool     // AirPlay/Cast HTTP identity probes
	NTLM            bool     // NTLMSSP challenge on SMB/RDP → Windows build + names
	Proxmox         bool     // unauthenticated Proxmox VE login page → identity + version
	ESPHome         bool     // ESPHome /events → device title + entity set
	TCPBehavioral   bool     // closed-port timing fingerprint
	ThoroughWake    bool     // extra wake pass for power-saving devices
	MaxProbesPerSec int
	CycleInterval   time.Duration
	Interface       string // egress interface override; empty → default-route interface

	// techniquesSet marks that the caller explicitly populated the technique
	// flags (buildCollectors does). When false, NewProber turns the classic set
	// on so existing zero-value callers keep working.
	techniquesSet bool
}

// WithTechniques returns cfg with the technique flags taken as authoritative
// (buildCollectors uses this so a deselected technique stays off).
func (c Config) WithTechniques() Config { c.techniquesSet = true; return c }

// Prober implements collector.Collector: it sweeps the configured scope on a
// cycle, gently and rate-limited, emitting liveness/binding/service observations.
type Prober struct {
	subnets         []string
	ports           []int
	udpPorts        []int
	icmpEnabled     bool
	tcpEnabled      bool
	udpEnabled      bool
	bannersOn       bool
	rdnsOn          bool
	arpTableOn      bool
	snmpOn          bool
	mdnsOn          bool
	mediaOn         bool
	ntlmOn          bool
	proxmoxOn       bool
	esphomeOn       bool
	tcpBehavior     bool
	thoroughWake    bool
	snmpCommunities []string
	mediaClient     *http.Client
	pveClient       *http.Client // accepts Proxmox's default self-signed certificate
	esphomeClient   *http.Client // no timeout of its own: /events never closes, so the context bounds it
	limiter         *limiter
	cycleInterval   time.Duration
	concurrency     int
	log             *slog.Logger

	interfaceName string     // egress interface override; empty → default-route
	sourceIP      netip.Addr // resolved at Run; zero = OS default routing

	connectTimeout, bannerTimeout, icmpTimeout, snmpTimeout, udpTimeout, mdnsTimeout time.Duration

	pinger *icmpPinger
}

// NewProber builds a prober from config with gentle defaults.
func NewProber(cfg Config, log *slog.Logger) *Prober {
	if log == nil {
		log = slog.Default()
	}
	cycle := cfg.CycleInterval
	if cycle <= 0 {
		cycle = 15 * time.Minute
	}
	// Back-compat: a zero-value Config (tests) didn't set the technique flags.
	// Default the classic sweep on so those callers behave as before.
	if !cfg.techniquesSet {
		cfg.TCP, cfg.UDP, cfg.Banners, cfg.ReverseDNS, cfg.ARPTable, cfg.SNMP = true, true, true, true, true, true
	}
	return &Prober{
		subnets:         cfg.Subnets,
		ports:           cfg.TCPPorts,
		udpPorts:        cfg.UDPPorts,
		icmpEnabled:     cfg.ICMP,
		tcpEnabled:      cfg.TCP,
		udpEnabled:      cfg.UDP,
		bannersOn:       cfg.Banners,
		rdnsOn:          cfg.ReverseDNS,
		arpTableOn:      cfg.ARPTable,
		snmpOn:          cfg.SNMP,
		mdnsOn:          cfg.MDNS,
		mediaOn:         cfg.Media,
		ntlmOn:          cfg.NTLM,
		proxmoxOn:       cfg.Proxmox,
		esphomeOn:       cfg.ESPHome,
		tcpBehavior:     cfg.TCPBehavioral,
		thoroughWake:    cfg.ThoroughWake,
		snmpCommunities: cfg.SNMPCommunities,
		mediaClient:     &http.Client{Timeout: 3 * time.Second},
		pveClient:       newSelfSignedClient(4 * time.Second),
		esphomeClient:   &http.Client{},
		limiter:         newLimiter(cfg.MaxProbesPerSec),
		cycleInterval:   cycle,
		concurrency:     32,
		interfaceName:   cfg.Interface,
		log:             log,
		connectTimeout:  2 * time.Second,
		bannerTimeout:   1500 * time.Millisecond,
		icmpTimeout:     time.Second,
		snmpTimeout:     1500 * time.Millisecond,
		udpTimeout:      2 * time.Second,
		mdnsTimeout:     1500 * time.Millisecond,
	}
}

func (p *Prober) Name() string { return "active" }

// Run sweeps the scope immediately, then once per cycle, until ctx is cancelled.
func (p *Prober) Run(ctx context.Context, sink *observation.Sink) error {
	if len(p.subnets) == 0 {
		return nil
	}

	// Pin egress to the management interface so probes never originate from a
	// capture/SPAN NIC (§4.1). On failure we fall back to OS default routing.
	if src, desc, err := resolveSourceIP(p.interfaceName); err != nil {
		p.log.Warn("active prober: could not bind egress interface, using OS default routing", "err", err)
	} else {
		p.sourceIP = src
		p.log.Info("active prober: egress bound", "interface", desc, "source_ip", src.String())
	}

	if p.icmpEnabled {
		if pinger, err := newICMPPinger(p.sourceIP); err != nil {
			p.log.Warn("active prober: ICMP unavailable, relying on TCP-connect liveness", "err", err)
		} else {
			p.pinger = pinger
			defer pinger.Close()
		}
	}

	p.sweep(ctx, sink)
	ticker := time.NewTicker(p.cycleInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			p.sweep(ctx, sink)
		}
	}
}

// sweep probes every target in scope with bounded concurrency, then harvests the
// kernel ARP cache for the L2 bindings the probing populated.
func (p *Prober) sweep(ctx context.Context, sink *observation.Sink) {
	targets, skipped, err := enumerateTargets(p.subnets)
	if err != nil {
		p.log.Error("active prober: bad scope", "err", err)
		return
	}
	for _, s := range skipped {
		p.log.Warn("active prober: subnet skipped", "detail", s)
	}
	p.log.Info("active sweep starting", "targets", len(targets))

	p.probeTargets(ctx, targets, sink)

	// Thorough Wake (opt-in, default ON): aggressively power-saving devices
	// (wired cameras, thermostats, smart plugs, TVs, sleeping phones) often miss
	// the first sweep. Pause briefly, then re-ping every target — the goal is to
	// populate the kernel neighbour table — and harvest ARP again. Trades a little
	// scan time for materially better coverage on mixed networks.
	if p.thoroughWake && p.pinger != nil && ctx.Err() == nil {
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
		p.log.Info("active sweep: thorough-wake pass", "targets", len(targets))
		for _, ip := range targets {
			if ctx.Err() != nil {
				break
			}
			if p.limiter.wait(ctx) != nil {
				break
			}
			_, _ = p.pinger.ping(ctx, ip, p.icmpTimeout)
		}
		if p.arpTableOn {
			p.harvestARP(ctx, targets, sink)
		}
	}

	p.log.Info("active sweep complete", "targets", len(targets))
}

// probeTargets probes every address with bounded concurrency, then harvests the
// kernel ARP cache for the L2 bindings the probing populated. Shared by the
// scheduled sweep and the on-demand ProbeOnce.
func (p *Prober) probeTargets(ctx context.Context, targets []netip.Addr, sink *observation.Sink) {
	sem := make(chan struct{}, p.concurrency)
	var wg sync.WaitGroup
	for _, ip := range targets {
		if ctx.Err() != nil {
			break
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(ip netip.Addr) {
			defer wg.Done()
			defer func() { <-sem }()
			defer func() {
				if r := recover(); r != nil {
					p.log.Error("active probe panicked (recovered)", "ip", ip.String(), "panic", r)
				}
			}()
			p.probeHost(ctx, ip, sink)
		}(ip)
	}
	wg.Wait()

	if p.arpTableOn {
		p.harvestARP(ctx, targets, sink)
	}
}

// ProbeOnce probes an explicit set of addresses a single time — the engine
// behind the UI "Rescan" action. It sets up and tears down its own egress
// binding + ICMP socket, so it works whether or not the scheduled sweep is
// running, and it ignores the configured scope (the targets are passed in). Best
// called on a Prober built just for this probe; it shares the same gentleness
// (rate limiter, bounded concurrency, SPAN-safe egress) as the scheduled sweep.
func (p *Prober) ProbeOnce(ctx context.Context, targets []netip.Addr, sink *observation.Sink) {
	if len(targets) == 0 {
		return
	}
	if src, desc, err := resolveSourceIP(p.interfaceName); err != nil {
		p.log.Warn("rescan: could not bind egress interface, using OS default routing", "err", err)
	} else {
		p.sourceIP = src
		p.log.Info("rescan: egress bound", "interface", desc, "source_ip", src.String())
	}
	if p.icmpEnabled {
		if pinger, err := newICMPPinger(p.sourceIP); err != nil {
			p.log.Warn("rescan: ICMP unavailable, relying on TCP-connect liveness", "err", err)
		} else {
			p.pinger = pinger
			defer pinger.Close()
		}
	}
	p.log.Info("rescan starting", "targets", len(targets))
	p.probeTargets(ctx, targets, sink)
	p.log.Info("rescan complete", "targets", len(targets))
}

// EnumerateTargets expands subnet CIDRs into the probeable host addresses, with
// the same scope guards the scheduled sweep uses (skips network/broadcast and
// over-large ranges). Exposed for the on-demand subnet rescan.
func EnumerateTargets(cidrs []string) (targets []netip.Addr, skipped []string, err error) {
	return enumerateTargets(cidrs)
}

// probeHost runs the probe sequence for one address, emitting only positive
// findings — a host that doesn't answer yields nothing (absence is not a fact).
func (p *Prober) probeHost(ctx context.Context, ip netip.Addr, sink *observation.Sink) {
	ipStr := ip.String()
	alive := false

	if p.pinger != nil {
		if p.limiter.wait(ctx) != nil {
			return
		}
		if ok, _ := p.pinger.ping(ctx, ip, p.icmpTimeout); ok {
			alive = true
			p.record(ctx, sink, emit{observation.SourceActiveICMP, observation.SubjectIPv4, ipStr, observation.AttrLiveness, "up", confICMPLive})
		}
	}

	// Which ports answered, so the follow-up identity probes below only run where
	// the scan already justifies them (§4.2: no speculative connections).
	open := map[int]bool{}

	if p.tcpEnabled {
		for _, port := range p.ports {
			if p.limiter.wait(ctx) != nil {
				return
			}
			res := probeTCP(ctx, ipStr, port, p.connectTimeout, p.bannerTimeout, p.sourceIP)
			switch {
			case res.open:
				alive = true
				open[port] = true
				pp := "tcp/" + strconv.Itoa(port)
				p.record(ctx, sink, emit{observation.SourceActiveTCP, observation.SubjectIPv4, ipStr, observation.AttrOpenPort, pp, confTCPOpen})
				p.record(ctx, sink, emit{observation.SourceActiveTCP, observation.SubjectIPv4, ipStr, observation.AttrLiveness, "up", confTCPLive})
				if p.bannersOn && res.banner != "" {
					p.record(ctx, sink, emit{observation.SourceActiveTCP, observation.SubjectIPv4, ipStr, observation.AttrServiceBanner, pp + "|" + res.banner, confTCPBanner})
					// An SSH banner frequently states the distribution and, on
					// Debian, the release outright. The inference layer reduces
					// the same string to bare "Linux"; this reads what it says.
					p.recordSSHDistro(ctx, sink, ipStr, res.banner)
				}
			case res.refused:
				alive = true
				p.record(ctx, sink, emit{observation.SourceActiveTCP, observation.SubjectIPv4, ipStr, observation.AttrLiveness, "up", confTCPLive})
			}
		}
	}

	// UDP service scan: only the operator-listed ports (never a default sweep).
	if p.udpEnabled {
		for _, port := range p.udpPorts {
			if p.limiter.wait(ctx) != nil {
				return
			}
			res := probeUDP(ctx, ipStr, port, p.udpTimeout, p.sourceIP)
			switch {
			case res.open:
				alive = true
				pp := "udp/" + strconv.Itoa(port)
				p.record(ctx, sink, emit{observation.SourceActiveUDP, observation.SubjectIPv4, ipStr, observation.AttrOpenPort, pp, confUDPOpen})
				p.record(ctx, sink, emit{observation.SourceActiveUDP, observation.SubjectIPv4, ipStr, observation.AttrLiveness, "up", confUDPLive})
			case res.refused:
				alive = true
				p.record(ctx, sink, emit{observation.SourceActiveUDP, observation.SubjectIPv4, ipStr, observation.AttrLiveness, "up", confUDPLive})
			}
		}
	}

	if !alive {
		return
	}

	// TCP behavioural fingerprint: time a connect to a (very likely) closed port
	// to infer the host's TCP-stack / firewall behaviour. A weak, corroborating
	// signal the inference layer folds into the OS guess.
	if p.tcpBehavior {
		if behavior := probeTCPBehavior(ctx, ipStr, p.connectTimeout, p.sourceIP, p.limiter); behavior != "" {
			p.record(ctx, sink, emit{observation.SourceActiveTCPBeh, observation.SubjectIPv4, ipStr, observation.AttrTCPBehavior, behavior, confTCPBehavior})
		}
	}

	if p.rdnsOn && p.limiter.wait(ctx) == nil {
		if name := reverseDNS(ctx, ipStr); name != "" {
			p.record(ctx, sink, emit{observation.SourceActiveRDNS, observation.SubjectIPv4, ipStr, observation.AttrHostname, name, confRDNSHost})
		}
	}

	if p.snmpOn && len(p.snmpCommunities) > 0 {
		// Find the first community this host answers to (via sysName), then reuse it
		// for sysDescr — so we don't re-try every community for the second OID.
		community := ""
		for _, c := range p.snmpCommunities {
			if c == "" {
				continue
			}
			if p.limiter.wait(ctx) != nil {
				break
			}
			if name, _ := snmpGet(ctx, ipStr, c, oidSysName, p.snmpTimeout, p.sourceIP); name != "" {
				community = c
				p.record(ctx, sink, emit{observation.SourceActiveSNMP, observation.SubjectIPv4, ipStr, observation.AttrHostname, name, confSNMPName})
				break
			}
		}
		if community != "" && p.limiter.wait(ctx) == nil {
			if descr, _ := snmpGet(ctx, ipStr, community, oidSysDescr, p.snmpTimeout, p.sourceIP); descr != "" {
				p.record(ctx, sink, emit{observation.SourceActiveSNMP, observation.SubjectIPv4, ipStr, observation.AttrOSGuess, descr, confSNMPDescr})
			}
		}
	}

	// Windows identity: an NTLMSSP CHALLENGE states the host's exact OS build and
	// its NetBIOS/DNS names. Gated on SMB or RDP already being open — the probe
	// never opens a port the scan didn't find. Unauthenticated: the exchange
	// stops at the CHALLENGE and never sends an AUTHENTICATE.
	if p.ntlmOn && (open[445] || open[3389]) && p.limiter.wait(ctx) == nil {
		p.recordNTLM(ctx, sink, ipStr, open[445], open[3389])
	}

	// Proxmox VE: the login page on 8006 states the hypervisor's identity and
	// version to anyone who asks. Gated on the port being open.
	if p.proxmoxOn && open[8006] && p.limiter.wait(ctx) == nil {
		p.recordProxmoxVE(ctx, sink, ipStr)
	}

	// Active mDNS: a unicast Bonjour query surfaces the device's own service
	// advertisements (Fire TV, Apple TV, Chromecast, Ring, Echo, printers, …) and
	// self-reported model= — SPAN-free, the highest-signal identity for consumer
	// gear. Routed through the same classifiers the passive sensor uses.
	var mf *mdnsFindings
	if p.mdnsOn && p.limiter.wait(ctx) == nil {
		mf = p.recordMDNS(ctx, sink, ipStr)
	}

	// Media identity probes: AirPlay (:49152) and Google Cast (:8008) expose an
	// exact model + name over unauthenticated HTTP. They're GATED to hosts the
	// mDNS query already flagged as AirPlay/Cast devices — so we don't hit those
	// ports on every host, only the handful worth the round-trip.
	if p.mediaOn && mf != nil {
		p.recordMedia(ctx, sink, ipStr, mf, open)
	}

	// lockdownd (TCP 62078) — iOS Wi-Fi sync, the service behind Finder/iTunes
	// pairing. A listener here is an iOS-family device and never a Mac, which
	// makes it the one positive tell an iPhone or iPad offers a scanner: they
	// advertise no _device-info, and their MACs are randomized per SSID by
	// default. IP Recon's M2 concluded the OPEN PORT is the signal — its TLS
	// QueryType handshake said no more about the family than the listener does.
	//
	// It cannot separate an iPhone from an iPad; that needs a paired GetValue,
	// which needs a trust relationship this project will never establish. The
	// family-level answer is where the evidence honestly stops.
	if open[62078] {
		p.record(ctx, sink, emit{observation.SourceActiveTCP, observation.SubjectIPv4, ipStr, observation.AttrDeviceClass, "Apple mobile device", confLockdownClass})
		p.record(ctx, sink, emit{observation.SourceActiveTCP, observation.SubjectIPv4, ipStr, observation.AttrOSGuess, "iOS", confLockdownOS})
	}

	// ESPHome: gated on the device's own _esphomelib advertisement, so the
	// /events stream is only opened where mDNS already proved what is listening.
	if p.esphomeOn && mf != nil && mf.hasService("_esphomelib") && p.limiter.wait(ctx) == nil {
		p.recordESPHome(ctx, sink, ipStr)
	}
}

// recordNTLM runs the Windows identity probe and emits what the CHALLENGE
// stated. os_guess stays the coarse family — the release goes in os_version, so
// the two are contested separately and the reconciler can attach the version to
// whichever "Windows" wins.
func (p *Prober) recordNTLM(ctx context.Context, sink *observation.Sink, ipStr string, smbOpen, rdpOpen bool) {
	r := probeNTLM(ctx, ipStr, smbOpen, rdpOpen, p.connectTimeout, p.sourceIP)
	if r == nil {
		return
	}
	src := observation.SourceActiveNTLM
	// The CHALLENGE proves Windows regardless of whether the build parsed: only
	// a Windows (or Samba) stack answers NTLM at all.
	p.record(ctx, sink, emit{src, observation.SubjectIPv4, ipStr, observation.AttrOSGuess, "Windows", confNTLMOS})
	if r.osVersion != "" {
		p.record(ctx, sink, emit{src, observation.SubjectIPv4, ipStr, observation.AttrOSVersion, r.osVersion, confNTLMOSVersion})
	}
	if name := r.hostname(); name != "" {
		p.record(ctx, sink, emit{src, observation.SubjectIPv4, ipStr, observation.AttrHostname, name, confNTLMHost})
	}
}

// recordESPHome emits what the /events stream volunteered. The entity-derived
// class is the strong claim; the title is the owner's label and is emitted as a
// hostname at a confidence that reflects being user-editable.
func (p *Prober) recordESPHome(ctx context.Context, sink *observation.Sink, ipStr string) {
	f := probeESPHome(ctx, ipStr, p.esphomeClient)
	if f == nil {
		return
	}
	src := observation.SourceActiveESPHome
	// Answering /events at all proves the firmware, which is the OS here.
	p.record(ctx, sink, emit{src, observation.SubjectIPv4, ipStr, observation.AttrOSGuess, "ESPHome", confESPHomeOS})
	if class := f.deviceClass(); class != "" {
		p.record(ctx, sink, emit{src, observation.SubjectIPv4, ipStr, observation.AttrDeviceClass, class, confESPHomeClass})
	} else {
		// Nothing specific in the entity set — an ESPHome board is still an IoT
		// device, and saying only that is the honest answer.
		p.record(ctx, sink, emit{src, observation.SubjectIPv4, ipStr, observation.AttrDeviceClass, "IoT device", confESPHomeGeneric})
	}
	if f.title != "" {
		p.record(ctx, sink, emit{src, observation.SubjectIPv4, ipStr, observation.AttrHostname, f.title, confESPHomeName})
	}
}

// orderByOpen returns candidates with the ones the scan found open moved to the
// front, preserving the relative order of each group. Every candidate is kept —
// this decides what to try FIRST, not what to try at all.
func orderByOpen(candidates []int, open map[int]bool) []int {
	out := make([]int, 0, len(candidates))
	for _, c := range candidates {
		if open[c] {
			out = append(out, c)
		}
	}
	for _, c := range candidates {
		if !open[c] {
			out = append(out, c)
		}
	}
	return out
}

// recordSSHDistro emits the distribution and release an SSH banner stated.
// Both come from the same source, so the reconciler's corroboration test
// attaches the release to the name whenever this reading wins.
func (p *Prober) recordSSHDistro(ctx context.Context, sink *observation.Sink, ipStr, banner string) {
	d := distroFromSSHBanner(banner)
	if d == nil {
		return
	}
	src := observation.SourceActiveTCP
	p.record(ctx, sink, emit{src, observation.SubjectIPv4, ipStr, observation.AttrOSGuess, d.name, d.nameConf})
	if d.version != "" {
		p.record(ctx, sink, emit{src, observation.SubjectIPv4, ipStr, observation.AttrOSVersion, d.version, d.versionConf})
	}
}

// recordProxmoxVE emits the hypervisor's identity, version and node name.
//
// "Proxmox VE" deliberately outranks the "Debian"/"Linux" that the SSH banner
// and inference produce for the same host: both are true, and the specific one
// is the useful one.
func (p *Prober) recordProxmoxVE(ctx context.Context, sink *observation.Sink, ipStr string) {
	f := probeProxmoxVE(ctx, ipStr, p.pveClient)
	if f == nil {
		return
	}
	src := observation.SourceActiveProxmoxVE
	p.record(ctx, sink, emit{src, observation.SubjectIPv4, ipStr, observation.AttrOSGuess, "Proxmox VE", confPVEOS})
	p.record(ctx, sink, emit{src, observation.SubjectIPv4, ipStr, observation.AttrDeviceClass, "server", confPVEClass})
	if f.version != "" {
		p.record(ctx, sink, emit{src, observation.SubjectIPv4, ipStr, observation.AttrOSVersion, f.version, confPVEVersion})
	}
	if f.nodeName != "" {
		p.record(ctx, sink, emit{src, observation.SubjectIPv4, ipStr, observation.AttrHostname, f.nodeName, confPVEHost})
	}
}

// recordMDNS runs one active mDNS query, emits device_class/os/model/hostname,
// and returns the findings (nil if the host answered nothing) so downstream
// probes can gate on what was advertised.
func (p *Prober) recordMDNS(ctx context.Context, sink *observation.Sink, ipStr string) *mdnsFindings {
	f := queryMDNS(ctx, ipStr, p.mdnsTimeout, p.sourceIP)
	if f == nil {
		return nil
	}
	src := observation.SourceActiveMDNS
	// Service types → device class / OS (e.g. _airplay → media / TV device).
	for _, svc := range f.services {
		if dev, os := passive.ClassifyMDNSService(svc); dev != "" || os != "" {
			if dev != "" {
				p.record(ctx, sink, emit{src, observation.SubjectIPv4, ipStr, observation.AttrDeviceClass, dev, confMDNSClass})
			}
			if os != "" {
				p.record(ctx, sink, emit{src, observation.SubjectIPv4, ipStr, observation.AttrOSGuess, os, confMDNSOS})
			}
		}
	}
	// TXT model= → OS + either an exact hardware model or a coarse device family.
	// An exact match is a real model (AttrModel, high conf); a prefix-only match
	// is a device class, mirroring the passive sensor's split.
	if f.model != "" {
		if dev, os, precise := passive.ClassifyMDNSModel(f.model); dev != "" || os != "" {
			if precise {
				p.record(ctx, sink, emit{src, observation.SubjectIPv4, ipStr, observation.AttrModel, dev, confMDNSModel})
			} else if dev != "" {
				p.record(ctx, sink, emit{src, observation.SubjectIPv4, ipStr, observation.AttrDeviceClass, dev, confMDNSModelGeneric})
			}
			if os != "" {
				p.record(ctx, sink, emit{src, observation.SubjectIPv4, ipStr, observation.AttrOSGuess, os, confMDNSOS})
			}
		}
	}
	if f.name != "" {
		p.record(ctx, sink, emit{src, observation.SubjectIPv4, ipStr, observation.AttrHostname, f.name, confMDNSHost})
	}
	return f
}

// recordMedia runs the media HTTP identity probes that the host's mDNS
// advertisement warrants: AirPlay only when an Apple AirPlay/RAOP service was
// seen, Google Cast (:8008) only when a Cast/DIAL service was seen.
//
// open ORDERS the AirPlay attempt — ports the scan found open are tried first,
// so a Mac (which answers on 7000) and an iOS device (49152) are each reached in
// one request. It is deliberately not a gate: the device's own mDNS
// advertisement is what justifies the probe, and an operator who trimmed the
// scanned-port list should not thereby lose the identification.
func (p *Prober) recordMedia(ctx context.Context, sink *observation.Sink, ipStr string, mf *mdnsFindings, open map[int]bool) {
	var probes []func(context.Context, string, *http.Client) mediaFindings
	if mf.hasService("_airplay", "_raop", "_airplay-p2p", "_appletv-v2") {
		ports := orderByOpen(airplayPorts, open)
		probes = append(probes, func(ctx context.Context, host string, c *http.Client) mediaFindings {
			return probeAirPlay(ctx, host, ports, c)
		})
	}
	if mf.hasService("_googlecast", "_dial", "_androidtvremote2") {
		probes = append(probes, probeGoogleCast)
	}
	for _, probe := range probes {
		if p.limiter.wait(ctx) != nil {
			return
		}
		f := probe(ctx, ipStr, p.mediaClient)
		if f.empty() {
			continue
		}
		src := observation.SourceActiveMedia
		if f.deviceClass != "" {
			p.record(ctx, sink, emit{src, observation.SubjectIPv4, ipStr, observation.AttrDeviceClass, f.deviceClass, confMediaClass})
		}
		if f.model != "" {
			p.record(ctx, sink, emit{src, observation.SubjectIPv4, ipStr, observation.AttrModel, f.model, confMediaModel})
		}
		if f.os != "" {
			p.record(ctx, sink, emit{src, observation.SubjectIPv4, ipStr, observation.AttrOSGuess, f.os, confMediaOS})
			// The version only ever accompanies the name from the same read — the
			// reconciler drops an os_version whose source did not also state the
			// winning os_guess, so emitting one without the other is wasted.
			if f.osVersion != "" {
				p.record(ctx, sink, emit{src, observation.SubjectIPv4, ipStr, observation.AttrOSVersion, f.osVersion, confMediaOSVersion})
			}
		}
		if f.name != "" {
			p.record(ctx, sink, emit{src, observation.SubjectIPv4, ipStr, observation.AttrHostname, f.name, confMediaName})
		}
	}
}

// harvestARP reads the kernel ARP cache and emits a ground-truth MAC↔IP binding
// for every in-scope address that resolved during the sweep.
func (p *Prober) harvestARP(ctx context.Context, targets []netip.Addr, sink *observation.Sink) {
	table := arpTable()
	if len(table) == 0 {
		return
	}
	inScope := make(map[string]bool, len(targets))
	for _, t := range targets {
		inScope[t.String()] = true
	}
	for ip, mac := range table {
		if !inScope[ip] {
			continue
		}
		p.record(ctx, sink, emit{observation.SourceActiveARP, observation.SubjectMAC, mac, observation.AttrIPBinding, ip, confARPBinding})
	}
}

func (p *Prober) record(ctx context.Context, sink *observation.Sink, e emit) {
	if _, err := sink.Record(ctx, e.source, e.subjectType, e.subject, e.attr, e.value, e.confidence); err != nil {
		p.log.Debug("active observation rejected", "attr", e.attr, "err", fmt.Sprint(err))
	}
}
