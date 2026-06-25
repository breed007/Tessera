// Package dhcp ingests DHCP server lease tables and emits them as high-confidence
// observations (IP↔MAC binding, hostname, and a reserved/dynamic lease class) so
// the reconciler can sharpen IP↔MAC↔hostname truth and the UI can distinguish
// reserved from dynamic addresses.
//
// This first source reads dnsmasq-family lease files — the format used by
// dnsmasq, Pi-hole, and OpenWrt — which need no auth (just a readable file path
// on the Tessera host). API-based sources (pfSense/OPNsense/Kea) are future
// adapters on the same observation shape.
package dhcp

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/tessera/tessera/internal/collector"
	"github.com/tessera/tessera/internal/observation"
)

const (
	confBinding  = 92 // authoritative server-side binding (slightly above passive ARP)
	confHostname = 86
	confLease    = 90
)

// Lease is one parsed DHCP lease.
type Lease struct {
	MAC      string
	IP       string
	Hostname string
}

// Config configures the lease-file collector.
type Config struct {
	Files    []string      // dnsmasq-family lease file paths
	Interval time.Duration // re-read cadence (default 5m)
}

// Collector polls one or more dnsmasq-family lease files.
type Collector struct {
	*collector.Health
	cfg Config
}

// New builds the lease-file collector.
func New(cfg Config) *Collector {
	if cfg.Interval <= 0 {
		cfg.Interval = 5 * time.Minute
	}
	return &Collector{Health: collector.NewHealth("dhcp-leases", "idle"), cfg: cfg}
}

func (c *Collector) Name() string { return "dhcp-leases" }

// Run re-reads the lease files every interval, emitting observations, until ctx
// is cancelled.
func (c *Collector) Run(ctx context.Context, sink *observation.Sink) error {
	t := time.NewTicker(c.cfg.Interval)
	defer t.Stop()
	c.runOnce(ctx, sink)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			c.runOnce(ctx, sink)
		}
	}
}

func (c *Collector) runOnce(ctx context.Context, sink *observation.Sink) {
	var leases int
	for _, path := range c.cfg.Files {
		ls, err := readLeaseFile(path)
		if err != nil {
			c.Failure(fmt.Errorf("read %s: %w", path, err))
			return
		}
		for _, l := range ls {
			if err := emitLease(ctx, sink, l); err != nil {
				c.Failure(err)
				return
			}
			leases++
		}
	}
	c.Success(fmt.Sprintf("read %d lease(s) from %d file(s)", leases, len(c.cfg.Files)))
}

// emitLease records the binding, hostname, and (dynamic) lease class for a lease.
func emitLease(ctx context.Context, sink *observation.Sink, l Lease) error {
	if l.MAC != "" && l.IP != "" {
		if _, err := sink.Record(ctx, observation.SourceDHCPLeases, observation.SubjectMAC, l.MAC, observation.AttrIPBinding, l.IP, confBinding); err != nil {
			return err
		}
		styp := observation.SubjectIPv4
		if strings.Contains(l.IP, ":") {
			styp = observation.SubjectIPv6
		}
		// dnsmasq lease files hold *dynamic* leases (static mappings live in config).
		if _, err := sink.Record(ctx, observation.SourceDHCPLeases, styp, l.IP, observation.AttrDHCPLease, "dynamic", confLease); err != nil {
			return err
		}
	}
	if l.MAC != "" && l.Hostname != "" {
		if _, err := sink.Record(ctx, observation.SourceDHCPLeases, observation.SubjectMAC, l.MAC, observation.AttrHostname, l.Hostname, confHostname); err != nil {
			return err
		}
	}
	return nil
}

func readLeaseFile(path string) ([]Lease, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []Lease
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if l, ok := parseLeaseLine(sc.Text()); ok {
			out = append(out, l)
		}
	}
	return out, sc.Err()
}

// parseLeaseLine parses one dnsmasq lease line:
//
//	<expiry-epoch> <mac> <ip> <hostname|*> <client-id|*>
//
// Returns ok=false for blank/garbage lines. A "*" hostname means none.
func parseLeaseLine(line string) (Lease, bool) {
	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) < 3 {
		return Lease{}, false
	}
	mac, ip := strings.ToLower(fields[1]), fields[2]
	if _, err := net.ParseMAC(mac); err != nil {
		return Lease{}, false
	}
	if net.ParseIP(ip) == nil {
		return Lease{}, false
	}
	host := ""
	if len(fields) >= 4 && fields[3] != "*" {
		host = fields[3]
	}
	return Lease{MAC: mac, IP: ip, Hostname: host}, true
}
