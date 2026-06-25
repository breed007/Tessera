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
	"github.com/tessera/tessera/internal/store"
)

// HostRow is a host plus its bound identities, for the inventory table.
type HostRow struct {
	entity.Host
	MACs    []string `json:"macs"`
	IPs     []string `json:"ips"`
	Vendor  string   `json:"vendor"`
	Online  bool     `json:"online"` // has at least one active address
	IconID  string   `json:"icon_id"`  // effective icon (manual or auto-assigned)
	IconURL string   `json:"icon_url"` // resolved asset path
}

// HostDetail is a host with everything attached to it, including the provenance
// trail (the observations that produced it).
type HostDetail struct {
	Host         entity.Host        `json:"host"`
	IconID       string             `json:"icon_id"`
	IconURL      string             `json:"icon_url"`
	Interfaces   []entity.Interface `json:"interfaces"`
	Addresses    []entity.Address   `json:"addresses"`
	Services     []entity.Service   `json:"services"`
	Topology     []entity.Topology  `json:"topology"`
	Observations []ObservationView  `json:"observations"`
	Changes      []ChangeView       `json:"changes"`
	Availability *AvailabilityView  `json:"availability,omitempty"`
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
			ObservedAt: o.ObservedAt, Source: string(o.Source), Subject: o.Subject,
			Attribute: string(o.Attribute), Value: o.Value, Confidence: o.Confidence,
		})
	}
	detail.Changes = computeChanges(obs)
	if evs, err := s.store.AvailabilityForHost(r.Context(), host.StableID); err == nil {
		detail.Availability = buildAvailability(evs, time.Now().UTC())
	}
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
	open := make([]entity.Conflict, 0)
	for _, c := range snap.Conflicts {
		if !c.Resolved && !resolvedKeys[conflictKey(c.Subject, c.Attribute)] {
			open = append(open, c)
		}
	}
	if resolved == nil {
		resolved = []entity.ConflictResolution{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"open": open, "resolved": resolved})
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
	n := 0
	for _, c := range snap.Conflicts {
		if !c.Resolved && !resolvedKeys[conflictKey(c.Subject, c.Attribute)] {
			n++
		}
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

func buildHostRows(snap entity.Snapshot) []HostRow {
	macsByHost := map[int64][]string{}
	vendorByHost := map[int64]string{}
	for _, i := range snap.Interfaces {
		macsByHost[i.HostID] = append(macsByHost[i.HostID], i.MAC)
		if vendorByHost[i.HostID] == "" && i.OUIVendor != "" {
			vendorByHost[i.HostID] = i.OUIVendor
		}
	}
	ipsByHost := map[int64][]string{}
	onlineByHost := map[int64]bool{}
	for _, a := range snap.Addresses {
		if a.HostID != nil {
			ipsByHost[*a.HostID] = append(ipsByHost[*a.HostID], a.IP)
			if a.State == entity.StateActive {
				onlineByHost[*a.HostID] = true
			}
		}
	}
	rows := make([]HostRow, 0, len(snap.Hosts))
	for _, h := range snap.Hosts {
		rows = append(rows, HostRow{Host: h, MACs: macsByHost[h.ID], IPs: ipsByHost[h.ID], Vendor: vendorByHost[h.ID], Online: onlineByHost[h.ID]})
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
