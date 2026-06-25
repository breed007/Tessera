package api

import (
	"fmt"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/tessera/tessera/internal/entity"
	"github.com/tessera/tessera/internal/portrisk"
)

// handleMetrics serves a Prometheus text-exposition snapshot of the current
// entity layer + collector health. Read-only; behind the normal auth gate, so
// Prometheus scrapes it with the API token (bearer_token in the scrape config).
// Hand-rolled exposition format — no client library, keeping the single static
// binary dependency-free.
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	snap, err := s.store.LoadEntities(ctx)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	supps, _ := s.store.ListSecuritySuppressions(ctx)
	now := time.Now().UTC()
	suppressed := map[string]bool{}
	for _, sp := range supps {
		if sp.Active(now) {
			suppressed[suppressionKey(sp.StableID, sp.Proto, sp.Port)] = true
		}
	}

	p := &promWriter{b: &strings.Builder{}}

	p.help("tessera_build_info", "Build version and number exposed as labels; value is always 1.", "gauge")
	p.line("tessera_build_info", map[string]string{"version": s.version, "build": s.build}, 1)

	// Devices by review state + total + online.
	activeHost := map[int64]bool{}
	for _, a := range snap.Addresses {
		if a.HostID != nil && a.State == entity.StateActive {
			activeHost[*a.HostID] = true
		}
	}
	var stNew, stExpected, stIgnored int
	for _, h := range snap.Hosts {
		switch {
		case h.Ignored:
			stIgnored++
		case h.IsExpected:
			stExpected++
		default:
			stNew++
		}
	}
	p.help("tessera_devices", "Known devices by review state (new, expected, ignored).", "gauge")
	p.line("tessera_devices", map[string]string{"state": "new"}, float64(stNew))
	p.line("tessera_devices", map[string]string{"state": "expected"}, float64(stExpected))
	p.line("tessera_devices", map[string]string{"state": "ignored"}, float64(stIgnored))
	p.help("tessera_devices_total", "Total known devices.", "gauge")
	p.line("tessera_devices_total", nil, float64(len(snap.Hosts)))
	p.help("tessera_devices_online", "Devices with at least one active address.", "gauge")
	p.line("tessera_devices_online", nil, float64(len(activeHost)))

	// Addresses by state.
	addrByState := map[entity.AddressState]int{}
	for _, a := range snap.Addresses {
		addrByState[a.State]++
	}
	p.help("tessera_addresses", "Reconciled IP addresses by binding state.", "gauge")
	for _, st := range []entity.AddressState{entity.StateActive, entity.StateStale, entity.StateReserved, entity.StateFree} {
		p.line("tessera_addresses", map[string]string{"state": string(st)}, float64(addrByState[st]))
	}

	// Subnets + per-subnet utilization (capacity from the CIDR prefix; used =
	// addresses reconciled into the subnet).
	usedBySubnet := map[int64]int{}
	for _, a := range snap.Addresses {
		if a.SubnetID != nil {
			usedBySubnet[*a.SubnetID]++
		}
	}
	p.help("tessera_subnets_total", "Number of known subnets.", "gauge")
	p.line("tessera_subnets_total", nil, float64(len(snap.Subnets)))
	p.help("tessera_subnet_addresses_used", "Addresses reconciled into a subnet.", "gauge")
	p.help("tessera_subnet_addresses_total", "Usable address capacity of a subnet (IPv4).", "gauge")
	p.help("tessera_subnet_utilization_ratio", "Used / usable for a subnet (0–1, IPv4).", "gauge")
	for _, sn := range snap.Subnets {
		labels := map[string]string{"cidr": sn.CIDR}
		if sn.Name != "" {
			labels["name"] = sn.Name
		}
		used := usedBySubnet[sn.ID]
		p.line("tessera_subnet_addresses_used", labels, float64(used))
		if cap := usableIPv4(sn.CIDR); cap > 0 {
			p.line("tessera_subnet_addresses_total", labels, float64(cap))
			p.line("tessera_subnet_utilization_ratio", labels, float64(used)/float64(cap))
		}
	}

	// Conflicts + reachable services.
	p.help("tessera_conflicts_open", "Open (unresolved) reconciliation conflicts.", "gauge")
	p.line("tessera_conflicts_open", nil, float64(len(snap.Conflicts)))
	p.help("tessera_services_total", "Reachable services discovered across all hosts.", "gauge")
	p.line("tessera_services_total", nil, float64(len(snap.Services)))

	// Security findings by severity (active, i.e. non-suppressed, non-ignored host).
	host := map[int64]entity.Host{}
	for _, h := range snap.Hosts {
		host[h.ID] = h
	}
	sev := map[string]int{"high": 0, "medium": 0, "low": 0}
	for _, sv := range snap.Services {
		if sv.HostID == nil {
			continue
		}
		h := host[*sv.HostID]
		if h.Ignored {
			continue
		}
		risk, ok := portrisk.Classify(sv.Port)
		if !ok || suppressed[suppressionKey(h.StableID, sv.Proto, sv.Port)] {
			continue
		}
		sev[risk.Severity]++
	}
	p.help("tessera_security_findings", "Active exposed-service findings by severity.", "gauge")
	for _, level := range []string{"high", "medium", "low"} {
		p.line("tessera_security_findings", map[string]string{"severity": level}, float64(sev[level]))
	}

	// Observation log size.
	if total, err := s.store.CountObservations(ctx); err == nil {
		p.help("tessera_observations_total", "Total observations in the append-only log.", "gauge")
		p.line("tessera_observations_total", nil, float64(total))
	}

	// Collector health.
	if s.statuses != nil {
		p.help("tessera_collector_up", "1 if the collector's last run succeeded, else 0.", "gauge")
		p.help("tessera_collector_last_run_seconds", "Seconds since the collector last ran (0 if never).", "gauge")
		for _, st := range s.statuses() {
			up := 0.0
			if st.State == "ok" {
				up = 1
			}
			p.line("tessera_collector_up", map[string]string{"collector": st.Name}, up)
			age := 0.0
			if !st.LastRun.IsZero() {
				age = now.Sub(st.LastRun.UTC()).Seconds()
			}
			p.line("tessera_collector_last_run_seconds", map[string]string{"collector": st.Name}, age)
		}
	}

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(p.b.String()))
}

// promWriter accumulates Prometheus exposition text, emitting each metric's
// HELP/TYPE header at most once.
type promWriter struct {
	b    *strings.Builder
	seen map[string]bool
}

func (p *promWriter) help(name, help, typ string) {
	if p.seen == nil {
		p.seen = map[string]bool{}
	}
	if p.seen[name] {
		return
	}
	p.seen[name] = true
	fmt.Fprintf(p.b, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, typ)
}

func (p *promWriter) line(name string, labels map[string]string, v float64) {
	p.b.WriteString(name)
	if len(labels) > 0 {
		keys := make([]string, 0, len(labels))
		for k := range labels {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		p.b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				p.b.WriteByte(',')
			}
			fmt.Fprintf(p.b, `%s="%s"`, k, escapeLabel(labels[k]))
		}
		p.b.WriteByte('}')
	}
	p.b.WriteByte(' ')
	p.b.WriteString(strconv.FormatFloat(v, 'g', -1, 64))
	p.b.WriteByte('\n')
}

func escapeLabel(v string) string {
	v = strings.ReplaceAll(v, `\`, `\\`)
	v = strings.ReplaceAll(v, `"`, `\"`)
	v = strings.ReplaceAll(v, "\n", `\n`)
	return v
}

// usableIPv4 returns the usable host count for an IPv4 CIDR (capacity minus
// network+broadcast for /30 and larger), or 0 for IPv6 / unparseable.
func usableIPv4(cidr string) int {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil || ipnet.IP.To4() == nil {
		return 0
	}
	ones, bits := ipnet.Mask.Size()
	host := bits - ones
	if host <= 1 {
		return 1 << host // /31, /32: no network/broadcast subtraction
	}
	return (1 << host) - 2
}
