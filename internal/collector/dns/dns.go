// Package dns ingests authoritative name↔IP records from whatever local DNS the
// network runs, so devices get their real DNS names (and those names can win the
// hostname conflict against coarser sources via a "prefer dns for hostname"
// precedence rule). It is deliberately DNS-server-agnostic — two kinds of source:
//
//   - Local files — hosts-format files (Pi-hole custom.list, dnsmasq addn-hosts,
//     /etc/hosts) and Unbound `local-data:` config. No auth; just a readable path
//     on the Tessera host. Covers dnsmasq, Unbound, and Pi-hole out of the box.
//   - A DNS server's HTTP API — AdGuard Home (rewrites), Pi-hole v6 (local DNS
//     records), or Technitium (zone A/AAAA records). One server, selected by type.
package dns

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
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

// Server type identifiers for the HTTP-API source.
const (
	ServerAdGuard    = "adguard"
	ServerPihole     = "pihole"
	ServerTechnitium = "technitium"
)

// Config configures the DNS records collector.
type Config struct {
	HostsFiles []string // hosts-format + Unbound local-data files, read as text

	// One optional DNS-server HTTP API. ServerType selects the dialect; blank = off.
	ServerType  string // "adguard" | "pihole" | "technitium"
	ServerURL   string // e.g. http://dns.lan:3000 (AdGuard), http://pi.hole (Pi-hole), http://dns.lan:5380 (Technitium)
	ServerUser  string // AdGuard basic-auth user (ignored by Pi-hole/Technitium)
	ServerToken string // secret: AdGuard password / Pi-hole app-password / Technitium API token

	Interval time.Duration // re-read cadence (default 5m)
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
		rs, err := readRecordsFile(path)
		if err != nil {
			firstErr = errOnce(firstErr, fmt.Errorf("%s: %w", path, err))
			continue
		}
		recs = append(recs, rs...)
	}
	if c.cfg.ServerType != "" && c.cfg.ServerURL != "" {
		rs, err := c.serverRecords(ctx)
		if err != nil {
			firstErr = errOnce(firstErr, fmt.Errorf("%s: %w", c.cfg.ServerType, err))
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

// ── local files ──────────────────────────────────────────────────────────────

// readRecordsFile parses a local DNS file. Each line is tried as a hosts-format
// entry ("IP name [alias...]") and, failing that, as an Unbound `local-data:`
// directive — so one path option covers dnsmasq/Pi-hole/hosts and Unbound configs.
func readRecordsFile(path string) ([]record, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []record
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if r, ok := parseHostsLine(line); ok {
			out = append(out, r)
		} else if r, ok := parseUnboundLine(line); ok {
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
	return record{IP: fields[0], Name: strings.TrimSuffix(name, ".")}, true
}

// parseUnboundLine parses an Unbound `local-data:` A/AAAA directive:
//
//	local-data: "host.lan. IN A 10.0.0.5"
//	local-data: "host.lan. AAAA fd00::5"
//
// PTR / other record types and the reverse `local-data-ptr:` form are skipped —
// the forward A/AAAA record is the name↔IP fact we want.
func parseUnboundLine(line string) (record, bool) {
	if i := strings.IndexByte(line, '#'); i >= 0 {
		line = line[:i]
	}
	line = strings.TrimSpace(line)
	rest, ok := strings.CutPrefix(line, "local-data:")
	if !ok {
		return record{}, false
	}
	rest = strings.TrimSpace(rest)
	rest = strings.Trim(rest, "\"'") // strip the quotes around the record
	fields := strings.Fields(rest)
	// name [TTL] [IN] <A|AAAA> ip  → need a name, an A/AAAA type token, and an IP.
	if len(fields) < 3 {
		return record{}, false
	}
	name := strings.TrimSuffix(fields[0], ".")
	var ip string
	for i := 1; i < len(fields); i++ {
		switch strings.ToUpper(fields[i]) {
		case "A", "AAAA":
			if i+1 < len(fields) && net.ParseIP(fields[i+1]) != nil {
				ip = fields[i+1]
			}
		}
	}
	if name == "" || ip == "" || strings.EqualFold(name, "localhost") {
		return record{}, false
	}
	return record{IP: ip, Name: name}, true
}

// ── HTTP-API sources ─────────────────────────────────────────────────────────

// serverRecords dispatches to the configured server dialect.
func (c *Collector) serverRecords(ctx context.Context) ([]record, error) {
	switch c.cfg.ServerType {
	case ServerAdGuard:
		return c.adguardRewrites(ctx)
	case ServerPihole:
		return c.piholeHosts(ctx)
	case ServerTechnitium:
		return c.technitiumRecords(ctx)
	default:
		return nil, fmt.Errorf("unknown server type %q", c.cfg.ServerType)
	}
}

func (c *Collector) get(ctx context.Context, u string, basicAuth bool) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, 0, err
	}
	if basicAuth && (c.cfg.ServerUser != "" || c.cfg.ServerToken != "") {
		req.SetBasicAuth(c.cfg.ServerUser, c.cfg.ServerToken)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	return body, resp.StatusCode, nil
}

// AdGuard Home: GET /control/rewrite/list → [{domain, answer}].
func (c *Collector) adguardRewrites(ctx context.Context) ([]record, error) {
	base := strings.TrimRight(c.cfg.ServerURL, "/")
	body, code, err := c.get(ctx, base+"/control/rewrite/list", true)
	if err != nil {
		return nil, err
	}
	if code == http.StatusUnauthorized {
		return nil, fmt.Errorf("401 — check the AdGuard username/password")
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", code)
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
			out = append(out, record{IP: strings.TrimSpace(e.Answer), Name: strings.TrimSuffix(strings.TrimSpace(e.Domain), ".")})
		}
	}
	return out, nil
}

// Pi-hole v6: authenticate (POST /api/auth {password}) → SID, then GET
// /api/config/dns/hosts?sid=… → {config:{dns:{hosts:["10.0.0.5 name", …]}}}.
// The host entries are hosts-format strings, reused through parseHostsLine.
func (c *Collector) piholeHosts(ctx context.Context) ([]record, error) {
	base := strings.TrimRight(c.cfg.ServerURL, "/")
	sid, err := c.piholeAuth(ctx, base)
	if err != nil {
		return nil, err
	}
	body, code, err := c.get(ctx, base+"/api/config/dns/hosts?sid="+url.QueryEscape(sid), false)
	if err != nil {
		return nil, err
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("hosts: HTTP %d", code)
	}
	return parsePiholeHosts(body)
}

func (c *Collector) piholeAuth(ctx context.Context, base string) (string, error) {
	reqBody := strings.NewReader(fmt.Sprintf(`{"password":%q}`, c.cfg.ServerToken))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/api/auth", reqBody)
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode == http.StatusUnauthorized {
		return "", fmt.Errorf("401 — check the Pi-hole app password")
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("auth: HTTP %d", resp.StatusCode)
	}
	var out struct {
		Session struct {
			Valid bool   `json:"valid"`
			SID   string `json:"sid"`
		} `json:"session"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", err
	}
	if out.Session.SID == "" {
		return "", fmt.Errorf("no session id returned (is this Pi-hole v6?)")
	}
	return out.Session.SID, nil
}

func parsePiholeHosts(body []byte) ([]record, error) {
	var out struct {
		Config struct {
			DNS struct {
				Hosts []string `json:"hosts"`
			} `json:"dns"`
		} `json:"config"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	var recs []record
	for _, h := range out.Config.DNS.Hosts {
		if r, ok := parseHostsLine(h); ok {
			recs = append(recs, r)
		}
	}
	return recs, nil
}

// Technitium: list zones (GET /api/zones/list?token=…) then pull each zone's
// records (GET /api/zones/records/get?…&listZone=true), keeping A/AAAA answers.
func (c *Collector) technitiumRecords(ctx context.Context) ([]record, error) {
	base := strings.TrimRight(c.cfg.ServerURL, "/")
	tok := url.QueryEscape(c.cfg.ServerToken)
	body, code, err := c.get(ctx, base+"/api/zones/list?token="+tok, false)
	if err != nil {
		return nil, err
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("zones/list: HTTP %d", code)
	}
	zones, err := parseTechnitiumZones(body)
	if err != nil {
		return nil, err
	}
	var recs []record
	for _, z := range zones {
		if ctx.Err() != nil {
			break
		}
		u := fmt.Sprintf("%s/api/zones/records/get?token=%s&domain=%s&zone=%s&listZone=true",
			base, tok, url.QueryEscape(z), url.QueryEscape(z))
		rb, rc, rerr := c.get(ctx, u, false)
		if rerr != nil || rc != http.StatusOK {
			continue // skip a zone we can't read rather than fail the whole poll
		}
		rs, _ := parseTechnitiumRecords(rb)
		recs = append(recs, rs...)
	}
	return recs, nil
}

func parseTechnitiumZones(body []byte) ([]string, error) {
	var out struct {
		Status   string `json:"status"`
		Response struct {
			Zones []struct {
				Name     string `json:"name"`
				Internal bool   `json:"internal"`
			} `json:"zones"`
		} `json:"response"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	if out.Status != "" && out.Status != "ok" {
		return nil, fmt.Errorf("technitium status %q (check the API token)", out.Status)
	}
	var zones []string
	for _, z := range out.Response.Zones {
		if z.Internal || z.Name == "" {
			continue // skip built-in zones (localhost, reverse stubs)
		}
		zones = append(zones, z.Name)
	}
	return zones, nil
}

func parseTechnitiumRecords(body []byte) ([]record, error) {
	var out struct {
		Response struct {
			Records []struct {
				Name  string `json:"name"`
				Type  string `json:"type"`
				RData struct {
					IPAddress string `json:"ipAddress"`
				} `json:"rData"`
			} `json:"records"`
		} `json:"response"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	var recs []record
	for _, r := range out.Response.Records {
		if (r.Type == "A" || r.Type == "AAAA") && r.Name != "" && net.ParseIP(r.RData.IPAddress) != nil {
			recs = append(recs, record{IP: r.RData.IPAddress, Name: strings.TrimSuffix(r.Name, ".")})
		}
	}
	return recs, nil
}

// TestServer verifies the configured DNS-server API and returns the record count.
func TestServer(ctx context.Context, cfg Config) (int, error) {
	rs, err := New(cfg).serverRecords(ctx)
	return len(rs), err
}

func errOnce(existing, err error) error {
	if existing != nil {
		return existing
	}
	return err
}
