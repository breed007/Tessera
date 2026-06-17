package api

import (
	"context"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/tessera/tessera/internal/entity"
)

// HostRow is a host plus its bound identities, for the inventory table.
type HostRow struct {
	entity.Host
	MACs    []string `json:"macs"`
	IPs     []string `json:"ips"`
	Vendor  string   `json:"vendor"`
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
	detail.IconID, detail.IconURL = s.effectiveIcon(host.Icon, vendor, host.OSGuess, host.DeviceClass)
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
	writeJSON(w, http.StatusOK, detail)
}

// handleObservations returns the most recent raw log entries (the observation
// drill-down). ?limit=N caps the result (default 300).
func (s *Server) handleObservations(w http.ResponseWriter, r *http.Request) {
	limit := 300
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	obs, err := s.store.RecentObservations(r.Context(), limit)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]ObservationView, 0, len(obs))
	for _, o := range obs {
		out = append(out, ObservationView{
			ObservedAt: o.ObservedAt, Source: string(o.Source), Subject: o.Subject,
			Attribute: string(o.Attribute), Value: o.Value, Confidence: o.Confidence,
		})
	}
	writeJSON(w, http.StatusOK, out)
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
	for _, a := range snap.Addresses {
		if a.HostID != nil {
			ipsByHost[*a.HostID] = append(ipsByHost[*a.HostID], a.IP)
		}
	}
	rows := make([]HostRow, 0, len(snap.Hosts))
	for _, h := range snap.Hosts {
		rows = append(rows, HostRow{Host: h, MACs: macsByHost[h.ID], IPs: ipsByHost[h.ID], Vendor: vendorByHost[h.ID]})
	}
	return rows
}

// withIcons fills the effective icon id + URL on each row.
func (s *Server) withIcons(rows []HostRow) []HostRow {
	for i := range rows {
		rows[i].IconID, rows[i].IconURL = s.effectiveIcon(rows[i].Icon, rows[i].Vendor, rows[i].OSGuess, rows[i].DeviceClass)
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
