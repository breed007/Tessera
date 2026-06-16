package active

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/tessera/tessera/internal/observation"
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
	SNMP            bool   // gate SNMP independently of the community being set
	SNMPCommunity   string // empty → SNMP disabled
	TCPBehavioral   bool   // closed-port timing fingerprint
	ThoroughWake    bool   // extra wake pass for power-saving devices
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
	subnets       []string
	ports         []int
	udpPorts      []int
	icmpEnabled   bool
	tcpEnabled    bool
	udpEnabled    bool
	bannersOn     bool
	rdnsOn        bool
	arpTableOn    bool
	snmpOn        bool
	tcpBehavior   bool
	thoroughWake  bool
	snmpCommunity string
	limiter       *limiter
	cycleInterval time.Duration
	concurrency   int
	log           *slog.Logger

	interfaceName string     // egress interface override; empty → default-route
	sourceIP      netip.Addr // resolved at Run; zero = OS default routing

	connectTimeout, bannerTimeout, icmpTimeout, snmpTimeout, udpTimeout time.Duration

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
		subnets:        cfg.Subnets,
		ports:          cfg.TCPPorts,
		udpPorts:       cfg.UDPPorts,
		icmpEnabled:    cfg.ICMP,
		tcpEnabled:     cfg.TCP,
		udpEnabled:     cfg.UDP,
		bannersOn:      cfg.Banners,
		rdnsOn:         cfg.ReverseDNS,
		arpTableOn:     cfg.ARPTable,
		snmpOn:         cfg.SNMP,
		tcpBehavior:    cfg.TCPBehavioral,
		thoroughWake:   cfg.ThoroughWake,
		snmpCommunity:  cfg.SNMPCommunity,
		limiter:        newLimiter(cfg.MaxProbesPerSec),
		cycleInterval:  cycle,
		concurrency:    32,
		interfaceName:  cfg.Interface,
		log:            log,
		connectTimeout: 2 * time.Second,
		bannerTimeout:  1500 * time.Millisecond,
		icmpTimeout:    time.Second,
		snmpTimeout:    1500 * time.Millisecond,
		udpTimeout:     2 * time.Second,
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

	if p.tcpEnabled {
		for _, port := range p.ports {
			if p.limiter.wait(ctx) != nil {
				return
			}
			res := probeTCP(ctx, ipStr, port, p.connectTimeout, p.bannerTimeout, p.sourceIP)
			switch {
			case res.open:
				alive = true
				pp := "tcp/" + strconv.Itoa(port)
				p.record(ctx, sink, emit{observation.SourceActiveTCP, observation.SubjectIPv4, ipStr, observation.AttrOpenPort, pp, confTCPOpen})
				p.record(ctx, sink, emit{observation.SourceActiveTCP, observation.SubjectIPv4, ipStr, observation.AttrLiveness, "up", confTCPLive})
				if p.bannersOn && res.banner != "" {
					p.record(ctx, sink, emit{observation.SourceActiveTCP, observation.SubjectIPv4, ipStr, observation.AttrServiceBanner, pp + "|" + res.banner, confTCPBanner})
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

	if p.snmpOn && p.snmpCommunity != "" {
		if p.limiter.wait(ctx) == nil {
			if name, _ := snmpGet(ctx, ipStr, p.snmpCommunity, oidSysName, p.snmpTimeout, p.sourceIP); name != "" {
				p.record(ctx, sink, emit{observation.SourceActiveSNMP, observation.SubjectIPv4, ipStr, observation.AttrHostname, name, confSNMPName})
			}
		}
		if p.limiter.wait(ctx) == nil {
			if descr, _ := snmpGet(ctx, ipStr, p.snmpCommunity, oidSysDescr, p.snmpTimeout, p.sourceIP); descr != "" {
				p.record(ctx, sink, emit{observation.SourceActiveSNMP, observation.SubjectIPv4, ipStr, observation.AttrOSGuess, descr, confSNMPDescr})
			}
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
