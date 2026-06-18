package api

import (
	"net/http"
	"sort"
	"strconv"

	"github.com/tessera/tessera/internal/entity"
	"github.com/tessera/tessera/internal/portrisk"
)

// SecFinding is one exposed-service / posture observation worth an operator's
// attention. Severity drives ordering and the badge colour.
type SecFinding struct {
	Severity string `json:"severity"` // high | medium | low
	Category string `json:"category"`
	Title    string `json:"title"`
	Detail   string `json:"detail"`
	StableID string `json:"stable_id"`
	Host     string `json:"host"`
	IP       string `json:"ip,omitempty"`
	Proto    string `json:"proto,omitempty"`
	Port     int    `json:"port,omitempty"`
}

// SecurityView is the Security page payload: findings (sorted high→low) + counts.
type SecurityView struct {
	Findings []SecFinding `json:"findings"`
	High     int          `json:"high"`
	Medium   int          `json:"medium"`
	Low      int          `json:"low"`
}

// largeAttackSurface flags a host with at least this many reachable services.
const largeAttackSurface = 12

func (s *Server) handleSecurity(w http.ResponseWriter, r *http.Request) {
	snap, err := s.store.LoadEntities(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	host := map[int64]entity.Host{}
	for _, h := range snap.Hosts {
		host[h.ID] = h
	}
	// Primary IP per host (prefer an active address).
	ipOf := map[int64]string{}
	for _, a := range snap.Addresses {
		if a.HostID == nil {
			continue
		}
		if ipOf[*a.HostID] == "" || a.State == entity.StateActive {
			ipOf[*a.HostID] = a.IP
		}
	}

	out := SecurityView{Findings: []SecFinding{}}
	count := map[int64]int{}
	for _, sv := range snap.Services {
		if sv.HostID == nil {
			continue
		}
		h := host[*sv.HostID]
		if h.Ignored {
			continue
		}
		count[*sv.HostID]++
		risk, ok := portrisk.Classify(sv.Port)
		if !ok {
			continue
		}
		out.Findings = append(out.Findings, SecFinding{
			Severity: risk.Severity, Category: risk.Category, Title: risk.Title, Detail: risk.Why,
			StableID: h.StableID, Host: hostLabel(h), IP: ipOf[h.ID], Proto: sv.Proto, Port: sv.Port,
		})
	}
	for id, n := range count {
		h := host[id]
		if h.Ignored || n < largeAttackSurface {
			continue
		}
		out.Findings = append(out.Findings, SecFinding{
			Severity: "low", Category: "attack-surface", Title: "Large attack surface",
			Detail: strconv.Itoa(n) + " reachable services on one host", StableID: h.StableID, Host: hostLabel(h), IP: ipOf[id],
		})
	}

	rank := map[string]int{"high": 0, "medium": 1, "low": 2}
	sort.SliceStable(out.Findings, func(i, j int) bool {
		a, b := out.Findings[i], out.Findings[j]
		if rank[a.Severity] != rank[b.Severity] {
			return rank[a.Severity] < rank[b.Severity]
		}
		if a.Host != b.Host {
			return a.Host < b.Host
		}
		return a.Port < b.Port
	})
	for _, f := range out.Findings {
		switch f.Severity {
		case "high":
			out.High++
		case "medium":
			out.Medium++
		default:
			out.Low++
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func hostLabel(h entity.Host) string {
	if h.DisplayName != "" {
		return h.DisplayName
	}
	return h.StableID
}

