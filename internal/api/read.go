package api

import (
	"context"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/tessera/tessera/internal/entity"
	"github.com/tessera/tessera/internal/observation"
	"github.com/tessera/tessera/internal/portrisk"
	"github.com/tessera/tessera/internal/store"
)

// HostRow is a host plus its bound identities, for the inventory table.
type HostRow struct {
	entity.Host
	MACs []string `json:"macs"`
	// IPs are ordered most-current-first (active before stale, then newest
	// last-seen); PrimaryIP is that head — the address the device is reachable
	// at now. The inventory table shows PrimaryIP so a device that has moved
	// around doesn't drag its whole address history across the row.
	IPs       []string `json:"ips"`
	PrimaryIP string   `json:"primary_ip"`
	// Subnets/VLANs the host holds addresses in (primary address first), so the
	// inventory can answer "show me everything on 10.0.20.0/24" or "on VLAN 20".
	Subnets []string `json:"subnets,omitempty"`
	VLANs   []int    `json:"vlans,omitempty"`
	Vendor  string   `json:"vendor"`
	Online  bool     `json:"online"`   // has at least one active address
	IconID  string   `json:"icon_id"`  // effective icon (manual or auto-assigned)
	IconURL string   `json:"icon_url"` // resolved asset path
}

// HostDetail is a host with everything attached to it, including the provenance
// trail (the observations that produced it).
type HostDetail struct {
	Host          entity.Host        `json:"host"`
	IconID        string             `json:"icon_id"`
	IconURL       string             `json:"icon_url"`
	Interfaces    []entity.Interface `json:"interfaces"`
	Addresses     []entity.Address   `json:"addresses"`
	Services      []entity.Service   `json:"services"`
	Topology      []entity.Topology  `json:"topology"`
	Observations  []ObservationView  `json:"observations"`
	Changes       []ChangeView       `json:"changes"`
	Availability  *AvailabilityView  `json:"availability,omitempty"`
	MergedFrom    []string           `json:"merged_from,omitempty"` // identities this host has absorbed
	SecHigh       int                `json:"sec_high"`              // active high-severity findings for this host
	SecFindings   int                `json:"sec_findings"`          // active findings (all severities)
	OpenConflicts int                `json:"open_conflicts"`        // unresolved conflicts on this host
}

// ChangeView is one meaningful change derived from the observation history — the
// device's timeline (IP changed, firmware bumped, a new service appeared).
type ChangeView struct {
	At   time.Time `json:"at"`
	Kind string    `json:"kind"` // ip | firmware | model | os | device | hostname | service
	From string    `json:"from,omitempty"`
	To   string    `json:"to,omitempty"`
}

// ObservationView is one log entry behind an entity (provenance, §1).
type ObservationView struct {
	ID         int64     `json:"id"`
	ObservedAt time.Time `json:"observed_at"`
	Source     string    `json:"source"`
	Subject    string    `json:"subject"`
	Attribute  string    `json:"attribute"`
	Value      string    `json:"value"`
	Confidence int       `json:"confidence"`
}

// Summary is the top-of-page counts.
type Summary struct {
	Hosts         int `json:"hosts"`
	Addresses     int `json:"addresses"`
	Subnets       int `json:"subnets"`
	Services      int `json:"services"`
	OpenConflicts int `json:"open_conflicts"`
	NewDevices    int `json:"new_devices"`
	Observations  int `json:"observations"`
}

func (s *Server) handleSummary(w http.ResponseWriter, r *http.Request) {
	snap, err := s.store.LoadEntities(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	obs, _ := s.store.CountObservations(r.Context())
	sum := Summary{
		Hosts:        len(snap.Hosts),
		Addresses:    len(snap.Addresses),
		Subnets:      len(snap.Subnets),
		Services:     len(snap.Services),
		Observations: int(obs),
	}
	sum.OpenConflicts = s.openConflictCount(r.Context(), snap)
	for _, h := range snap.Hosts {
		if !h.IsExpected {
			sum.NewDevices++
		}
	}
	writeJSON(w, http.StatusOK, sum)
}

func (s *Server) handleHosts(w http.ResponseWriter, r *http.Request) {
	snap, err := s.store.LoadEntities(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	rows := buildHostRows(snap)
	// Newest-seen first — what changed most recently is most interesting.
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].LastSeen.After(rows[j].LastSeen) })
	writeJSON(w, http.StatusOK, s.withIcons(rows))
}

func (s *Server) handleHost(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		writeErr(w, http.StatusBadRequest, "missing id")
		return
	}
	snap, err := s.store.LoadEntities(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	host, ok := findHost(snap, id)
	if !ok {
		writeErr(w, http.StatusNotFound, "host not found")
		return
	}
	detail := HostDetail{Host: host}
	subjects := []string{host.StableID}
	if v := stableIDValue(host.StableID); v != "" {
		subjects = append(subjects, v)
	}
	vendor := ""
	for _, i := range snap.Interfaces {
		if i.HostID == host.ID {
			detail.Interfaces = append(detail.Interfaces, i)
			subjects = append(subjects, i.MAC)
			if vendor == "" {
				vendor = i.OUIVendor
			}
		}
	}
	detail.IconID, detail.IconURL = s.effectiveIcon(host.Icon, vendor, host.OSGuess, host.DeviceClass, host.Model)
	for _, a := range snap.Addresses {
		if a.HostID != nil && *a.HostID == host.ID {
			detail.Addresses = append(detail.Addresses, a)
			subjects = append(subjects, a.IP)
		}
	}
	// Most-current first, so the detail header's primary IP is the address the
	// device actually answers on and the rest read as its address history.
	sortAddressesByRecency(detail.Addresses)
	for _, sv := range snap.Services {
		if sv.HostID != nil && *sv.HostID == host.ID {
			detail.Services = append(detail.Services, sv)
		}
	}
	for _, tp := range snap.Topology {
		if tp.HostID == host.ID {
			detail.Topology = append(detail.Topology, tp)
		}
	}
	obs, _ := s.store.ForSubjects(r.Context(), dedupe(subjects))
	for _, o := range obs {
		detail.Observations = append(detail.Observations, ObservationView{
			ID: o.ID, ObservedAt: o.ObservedAt, Source: string(o.Source), Subject: o.Subject,
			Attribute: string(o.Attribute), Value: o.Value, Confidence: o.Confidence,
		})
	}
	detail.Changes = computeChanges(obs)
	if evs, err := s.store.AvailabilityForHost(r.Context(), host.StableID); err == nil {
		detail.Availability = buildAvailability(evs, time.Now().UTC())
	}
	if ms, err := s.store.ListMerges(r.Context()); err == nil {
		detail.MergedFrom = mergedInto(ms, host.StableID)
	}
	detail.SecHigh, detail.SecFindings, detail.OpenConflicts = s.hostIssues(r.Context(), host, detail.Services, snap)
	writeJSON(w, http.StatusOK, detail)
}

// computeChanges derives a device's change timeline from its raw observations
// (passed newest-first). It walks chronologically, emitting an entry whenever a
// tracked attribute's value changes — IP (v4/v6 tracked separately to avoid
// dual-stack flapping), firmware, model, OS, device class, hostname — and when a
// new service/port first appears. Returns newest-first, capped.
func computeChanges(obs []observation.Observation) []ChangeView {
	asc := make([]observation.Observation, len(obs))
	for i, o := range obs {
		asc[len(obs)-1-i] = o
	}
	kinds := map[observation.Attribute]string{
		observation.AttrFirmware:    "firmware",
		observation.AttrModel:       "model",
		observation.AttrOSGuess:     "os",
		observation.AttrDeviceClass: "device",
		observation.AttrHostname:    "hostname",
	}
	last := map[observation.Attribute]string{}
	var lastIP4, lastIP6 string
	seenPort := map[string]bool{}
	var out []ChangeView
	for _, o := range asc {
		if kind, ok := kinds[o.Attribute]; ok {
			if prev, seen := last[o.Attribute]; seen && prev != o.Value && o.Value != "" {
				out = append(out, ChangeView{At: o.ObservedAt, Kind: kind, From: prev, To: o.Value})
			}
			last[o.Attribute] = o.Value
			continue
		}
		switch o.Attribute {
		case observation.AttrIPBinding:
			if strings.Contains(o.Value, ":") {
				if lastIP6 != "" && lastIP6 != o.Value {
					out = append(out, ChangeView{At: o.ObservedAt, Kind: "ip", From: lastIP6, To: o.Value})
				}
				lastIP6 = o.Value
			} else {
				if lastIP4 != "" && lastIP4 != o.Value {
					out = append(out, ChangeView{At: o.ObservedAt, Kind: "ip", From: lastIP4, To: o.Value})
				}
				lastIP4 = o.Value
			}
		case observation.AttrOpenPort:
			if !seenPort[o.Value] {
				seenPort[o.Value] = true
				out = append(out, ChangeView{At: o.ObservedAt, Kind: "service", To: o.Value})
			}
		}
	}
	// Newest-first, capped.
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	if len(out) > 50 {
		out = out[:50]
	}
	return out
}

// ObservationsPage is a filtered, paginated slice of the log plus the totals and
// facet lists the searchable observations page needs.
type ObservationsPage struct {
	Rows       []ObservationView `json:"rows"`
	Total      int               `json:"total"`
	Offset     int               `json:"offset"`
	Sources    []string          `json:"sources,omitempty"`
	Attributes []string          `json:"attributes,omitempty"`
}

// handleObservations serves the observations page: filterable by source,
// attribute, and a subject/value substring, paginated by limit/offset. Facets
// (distinct sources/attributes) are included on the first page for the dropdowns.
func (s *Server) handleObservations(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit := atoiDefault(q.Get("limit"), 200)
	offset := atoiDefault(q.Get("offset"), 0)
	obs, total, err := s.store.QueryObservations(r.Context(), store.ObservationFilter{
		Source: q.Get("source"), Attribute: q.Get("attribute"), Query: q.Get("q"),
		Limit: limit, Offset: offset,
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	page := ObservationsPage{Rows: make([]ObservationView, 0, len(obs)), Total: total, Offset: offset}
	for _, o := range obs {
		page.Rows = append(page.Rows, ObservationView{
			ObservedAt: o.ObservedAt, Source: string(o.Source), Subject: o.Subject,
			Attribute: string(o.Attribute), Value: o.Value, Confidence: o.Confidence,
		})
	}
	if offset == 0 {
		page.Sources, page.Attributes, _ = s.store.ObservationFacets(r.Context())
	}
	writeJSON(w, http.StatusOK, page)
}

func atoiDefault(s string, def int) int {
	if n, err := strconv.Atoi(s); err == nil && n >= 0 {
		return n
	}
	return def
}

func (s *Server) handleSubnets(w http.ResponseWriter, r *http.Request) {
	snap, err := s.store.LoadEntities(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, snap.Subnets)
}

// handleConflicts returns the conflict workflow: live disagreements still open,
// and the operator's recorded resolutions (which value is source of truth).
func (s *Server) handleConflicts(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	snap, err := s.store.LoadEntities(ctx)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	resolved, err := s.store.ListResolutions(ctx)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	resolvedKeys := map[string]bool{}
	for _, rr := range resolved {
		resolvedKeys[conflictKey(rr.Subject, rr.Attribute)] = true
	}
	// Source-precedence policy auto-resolves any conflict on a covered attribute
	// whose preferred source is one of the two sides.
	precedence, _ := s.store.ListPrecedence(ctx)
	prefByAttr := map[string]string{}
	for _, p := range precedence {
		prefByAttr[p.Attribute] = p.Source
	}
	open := make([]entity.Conflict, 0)
	for _, c := range snap.Conflicts {
		if c.Resolved || resolvedKeys[conflictKey(c.Subject, c.Attribute)] {
			continue
		}
		if pref, ok := prefByAttr[c.Attribute]; ok && (pref == c.SourceA || pref == c.SourceB) {
			continue // resolved by policy
		}
		open = append(open, c)
	}
	if resolved == nil {
		resolved = []entity.ConflictResolution{}
	}
	if precedence == nil {
		precedence = []entity.SourcePrecedence{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"open": open, "resolved": resolved, "precedence": precedence})
}

// hostIssues counts the active security findings (and high-severity subset) and
// the open conflicts for one host, so its detail page can flag problems where the
// device lives instead of making the operator hunt the Security/Conflicts pages.
func (s *Server) hostIssues(ctx context.Context, host entity.Host, services []entity.Service, snap entity.Snapshot) (high, findings, conflicts int) {
	supps, _ := s.store.ListSecuritySuppressions(ctx)
	now := time.Now().UTC()
	suppressed := map[string]bool{}
	for _, sp := range supps {
		if sp.Active(now) {
			suppressed[suppressionKey(sp.StableID, sp.Proto, sp.Port)] = true
		}
	}
	for _, sv := range services {
		risk, ok := portrisk.Classify(sv.Port)
		if !ok || suppressed[suppressionKey(host.StableID, sv.Proto, sv.Port)] {
			continue
		}
		findings++
		if risk.Severity == "high" {
			high++
		}
	}
	resolved, _ := s.store.ListResolutions(ctx)
	resolvedKeys := map[string]bool{}
	for _, rr := range resolved {
		resolvedKeys[conflictKey(rr.Subject, rr.Attribute)] = true
	}
	prec, _ := s.store.ListPrecedence(ctx)
	pref := map[string]string{}
	for _, p := range prec {
		pref[p.Attribute] = p.Source
	}
	for _, c := range snap.Conflicts {
		if c.Subject != host.StableID || c.Resolved || resolvedKeys[conflictKey(c.Subject, c.Attribute)] {
			continue
		}
		if p, ok := pref[c.Attribute]; ok && (p == c.SourceA || p == c.SourceB) {
			continue
		}
		conflicts++
	}
	return high, findings, conflicts
}

// conflictKey is the stable identity of a conflict / resolution across rebuilds
// (the numeric conflict id is reassigned each reconcile).
func conflictKey(subject, attribute string) string { return subject + "\x1f" + attribute }

// openConflictCount returns the number of live conflicts without a resolution.
func (s *Server) openConflictCount(ctx context.Context, snap entity.Snapshot) int {
	resolved, err := s.store.ListResolutions(ctx)
	if err != nil {
		resolved = nil
	}
	resolvedKeys := map[string]bool{}
	for _, rr := range resolved {
		resolvedKeys[conflictKey(rr.Subject, rr.Attribute)] = true
	}
	precedence, _ := s.store.ListPrecedence(ctx)
	prefByAttr := map[string]string{}
	for _, p := range precedence {
		prefByAttr[p.Attribute] = p.Source
	}
	n := 0
	for _, c := range snap.Conflicts {
		if c.Resolved || resolvedKeys[conflictKey(c.Subject, c.Attribute)] {
			continue
		}
		if pref, ok := prefByAttr[c.Attribute]; ok && (pref == c.SourceA || pref == c.SourceB) {
			continue
		}
		n++
	}
	return n
}

// handleNewDevices surfaces hosts not yet marked expected — the "new / unexpected
// device" view, newest first.
func (s *Server) handleNewDevices(w http.ResponseWriter, r *http.Request) {
	snap, err := s.store.LoadEntities(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	rows := buildHostRows(snap)
	out := make([]HostRow, 0)
	for _, row := range rows {
		if !row.IsExpected {
			out = append(out, row)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].FirstSeen.After(out[j].FirstSeen) })
	writeJSON(w, http.StatusOK, s.withIcons(out))
}

// ── helpers ──────────────────────────────────────────────────────────────────

// sortAddressesByRecency orders a host's addresses "most current first": active
// addresses ahead of stale/reserved/free, then newest last-seen. The head of the
// slice is therefore the address the device is reachable at right now, which is
// what the inventory table shows and what the detail header calls the primary IP.
func sortAddressesByRecency(addrs []entity.Address) {
	sort.SliceStable(addrs, func(i, j int) bool {
		ai, aj := addrs[i].State == entity.StateActive, addrs[j].State == entity.StateActive
		if ai != aj {
			return ai // active wins
		}
		return addrs[i].LastSeen.After(addrs[j].LastSeen)
	})
}

func buildHostRows(snap entity.Snapshot) []HostRow {
	macsByHost := map[int64][]string{}
	vendorByHost := map[int64]string{}
	for _, i := range snap.Interfaces {
		macsByHost[i.HostID] = append(macsByHost[i.HostID], i.MAC)
		if vendorByHost[i.HostID] == "" && i.OUIVendor != "" {
			vendorByHost[i.HostID] = i.OUIVendor
		}
	}
	addrsByHost := map[int64][]entity.Address{}
	onlineByHost := map[int64]bool{}
	for _, a := range snap.Addresses {
		if a.HostID != nil {
			addrsByHost[*a.HostID] = append(addrsByHost[*a.HostID], a)
			if a.State == entity.StateActive {
				onlineByHost[*a.HostID] = true
			}
		}
	}
	subnetByID := map[int64]entity.Subnet{}
	for _, sn := range snap.Subnets {
		subnetByID[sn.ID] = sn
	}
	rows := make([]HostRow, 0, len(snap.Hosts))
	for _, h := range snap.Hosts {
		addrs := addrsByHost[h.ID]
		sortAddressesByRecency(addrs)
		ips := make([]string, 0, len(addrs))
		var subnets []string
		var vlans []int
		seenSub, seenVLAN := map[string]bool{}, map[int]bool{}
		for _, a := range addrs {
			ips = append(ips, a.IP)
			if a.SubnetID == nil {
				continue
			}
			sn, ok := subnetByID[*a.SubnetID]
			if !ok {
				continue
			}
			if sn.CIDR != "" && !seenSub[sn.CIDR] {
				seenSub[sn.CIDR] = true
				subnets = append(subnets, sn.CIDR)
			}
			if sn.VLANID != nil && !seenVLAN[*sn.VLANID] {
				seenVLAN[*sn.VLANID] = true
				vlans = append(vlans, *sn.VLANID)
			}
		}
		primary := ""
		if len(ips) > 0 {
			primary = ips[0]
		}
		rows = append(rows, HostRow{
			Host: h, MACs: macsByHost[h.ID], IPs: ips, PrimaryIP: primary,
			Subnets: subnets, VLANs: vlans,
			Vendor: vendorByHost[h.ID], Online: onlineByHost[h.ID],
		})
	}
	return rows
}

// withIcons fills the effective icon id + URL on each row.
func (s *Server) withIcons(rows []HostRow) []HostRow {
	for i := range rows {
		rows[i].IconID, rows[i].IconURL = s.effectiveIcon(rows[i].Icon, rows[i].Vendor, rows[i].OSGuess, rows[i].DeviceClass, rows[i].Model)
	}
	return rows
}

func findHost(snap entity.Snapshot, id string) (entity.Host, bool) {
	for _, h := range snap.Hosts {
		if h.StableID == id {
			return h, true
		}
	}
	return entity.Host{}, false
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	out := in[:0]
	for _, v := range in {
		if v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}
