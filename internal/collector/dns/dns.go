// Package dns ingests authoritative name↔IP records from local DNS so devices get
// their real DNS names (and those names can win the hostname conflict against
// coarser sources via a precedence rule). Two source types, both emitting an
// AttrHostname keyed to the IP:
//
//   - hosts-format files — Pi-hole custom.list, dnsmasq addn-hosts, Unbound, and
//     /etc/hosts. No auth; just a readable path on the Tessera host.
//   - AdGuard Home — pulls DNS rewrites (custom A records) over the REST API.
package dns

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/tessera/tessera/internal/collector"
	"github.com/tessera/tessera/internal/observation"
)

// confDNSName is the confidence for a name from an authoritative DNS record —
// strong (first-party from the resolver), above reverse-DNS probes. Set a
// "prefer dns for hostname" precedence rule if you want it to always win.
const confDNSName = 84

// Config configures the DNS records collector.
type Config struct {
	HostsFiles  []string      // hosts-format files (Pi-hole/dnsmasq/Unbound//etc/hosts)
	AdGuardURL  string        // e.g. http://adguard.lan:3000  (blank = off)
	AdGuardUser string        // AdGuard web admin user (blank = no auth)
	AdGuardPass string        // AdGuard web admin password (secret)
	Interval    time.Duration // re-read cadence (default 5m)
}

// record is one resolved name↔IP mapping.
type record struct {
	IP   string
	Name string
}

// Collector polls the configured DNS sources.
type Collector struct {
	*collector.Health
	cfg  Config
	http *http.Client
}

// New builds the DNS collector.
func New(cfg Config) *Collector {
	if cfg.Interval <= 0 {
		cfg.Interval = 5 * time.Minute
	}
	return &Collector{Health: collector.NewHealth("dns", "idle"), cfg: cfg, http: &http.Client{Timeout: 20 * time.Second}}
}

func (c *Collector) Name() string { return "dns" }

// Run re-reads the sources every interval until ctx is cancelled.
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
	var recs []record
	var firstErr error
	for _, path := range c.cfg.HostsFiles {
		rs, err := readHostsFile(path)
		if err != nil {
			firstErr = errOnce(firstErr, fmt.Errorf("%s: %w", path, err))
			continue
		}
		recs = append(recs, rs...)
	}
	if c.cfg.AdGuardURL != "" {
		rs, err := c.adguardRewrites(ctx)
		if err != nil {
			firstErr = errOnce(firstErr, fmt.Errorf("adguard: %w", err))
		} else {
			recs = append(recs, rs...)
		}
	}

	written := 0
	for _, r := range recs {
		if ctx.Err() != nil {
			return
		}
		styp := observation.SubjectIPv4
		if strings.Contains(r.IP, ":") {
			styp = observation.SubjectIPv6
		}
		if _, err := sink.Record(ctx, observation.SourceDNS, styp, r.IP, observation.AttrHostname, r.Name, confDNSName); err != nil {
			continue
		}
		written++
	}
	if firstErr != nil && written == 0 {
		c.Failure(firstErr)
		return
	}
	c.Success(fmt.Sprintf("%d DNS record(s)", written))
}

// readHostsFile parses a hosts-format file: "IP name [alias...]", '#' comments.
// Only the first (canonical) name per line is taken.
func readHostsFile(path string) ([]record, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []record
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if r, ok := parseHostsLine(sc.Text()); ok {
			out = append(out, r)
		}
	}
	return out, sc.Err()
}

func parseHostsLine(line string) (record, bool) {
	if i := strings.IndexByte(line, '#'); i >= 0 {
		line = line[:i]
	}
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return record{}, false
	}
	if net.ParseIP(fields[0]) == nil {
		return record{}, false
	}
	name := fields[1]
	if name == "" || strings.EqualFold(name, "localhost") {
		return record{}, false
	}
	return record{IP: fields[0], Name: name}, true
}

// adguardRewrites pulls custom DNS rewrites (A-record answers) from AdGuard Home.
func (c *Collector) adguardRewrites(ctx context.Context) ([]record, error) {
	url := strings.TrimRight(c.cfg.AdGuardURL, "/") + "/control/rewrite/list"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if c.cfg.AdGuardUser != "" || c.cfg.AdGuardPass != "" {
		req.SetBasicAuth(c.cfg.AdGuardUser, c.cfg.AdGuardPass)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("401 — check the AdGuard username/password")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s", resp.Status)
	}
	return parseAdGuardRewrites(body)
}

func parseAdGuardRewrites(body []byte) ([]record, error) {
	var list []struct {
		Domain string `json:"domain"`
		Answer string `json:"answer"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		return nil, err
	}
	var out []record
	for _, e := range list {
		// Only A/AAAA rewrites (answer is an IP) map a name to a host; CNAME/
		// wildcard answers aren't address records.
		if net.ParseIP(strings.TrimSpace(e.Answer)) != nil && strings.TrimSpace(e.Domain) != "" && !strings.Contains(e.Domain, "*") {
			out = append(out, record{IP: strings.TrimSpace(e.Answer), Name: strings.TrimSpace(e.Domain)})
		}
	}
	return out, nil
}

// TestAdGuard verifies the AdGuard connection and returns the rewrite count.
func TestAdGuard(ctx context.Context, cfg Config) (int, error) {
	rs, err := New(cfg).adguardRewrites(ctx)
	return len(rs), err
}

func errOnce(existing, err error) error {
	if existing != nil {
		return existing
	}
	return err
}
