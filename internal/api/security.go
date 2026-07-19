package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/tessera/tessera/internal/entity"
	"github.com/tessera/tessera/internal/portrisk"
)

// SecFinding is one exposed-service / posture observation worth an operator's
// attention. Severity drives ordering and the badge colour.
type SecFinding struct {
	Severity     string `json:"severity"` // high | medium | low
	Category     string `json:"category"`
	Title        string `json:"title"`
	Detail       string `json:"detail"`
	StableID     string `json:"stable_id"`
	Host         string `json:"host"`
	IP           string `json:"ip,omitempty"`
	Proto        string `json:"proto,omitempty"`
	Port         int    `json:"port,omitempty"`
	Note         string     `json:"note,omitempty"`          // operator note when suppressed
	SuppressedBy string     `json:"suppressed_by,omitempty"` // who acknowledged it
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`    // nil = indefinite
}

// SecurityView is the Security page payload: active findings (sorted high→low) +
// counts, plus the separately-listed suppressed (acknowledged) findings.
type SecurityView struct {
	Findings   []SecFinding `json:"findings"`
	Suppressed []SecFinding `json:"suppressed"`
	High       int          `json:"high"`
	Medium     int          `json:"medium"`
	Low        int          `json:"low"`
}

// largeAttackSurface flags a host with at least this many reachable services.
const largeAttackSurface = 12

// suppressionKey identifies a finding for the suppress/acknowledge workflow. A
// host-level finding (large attack surface) has port 0 and proto "".
func suppressionKey(stableID, proto string, port int) string {
	return fmt.Sprintf("%s\x1f%s/%d", stableID, proto, port)
}

func (s *Server) handleSecurity(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	snap, err := s.store.LoadEntities(ctx)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	supps, err := s.store.ListSecuritySuppressions(ctx)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	now := time.Now().UTC()
	suppByKey := map[string]entity.SecuritySuppression{}
	for _, sp := range supps {
		if sp.Active(now) {
			suppByKey[suppressionKey(sp.StableID, sp.Proto, sp.Port)] = sp
			continue
		}
		// Expired — drop it so the finding resurfaces, and lazily purge the row.
		_ = s.store.DeleteSecuritySuppression(ctx, sp.StableID, sp.Proto, sp.Port)
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

	var all []SecFinding
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
		all = append(all, SecFinding{
			Severity: risk.Severity, Category: risk.Category, Title: risk.Title, Detail: risk.Why,
			StableID: h.StableID, Host: hostLabel(h), IP: ipOf[h.ID], Proto: sv.Proto, Port: sv.Port,
		})
	}
	for id, n := range count {
		h := host[id]
		if h.Ignored || n < largeAttackSurface {
			continue
		}
		all = append(all, SecFinding{
			Severity: "low", Category: "attack-surface", Title: "Large attack surface",
			Detail: strconv.Itoa(n) + " reachable services on one host", StableID: h.StableID, Host: hostLabel(h), IP: ipOf[id],
		})
	}

	// Partition into active vs suppressed (acknowledged), then count active only.
	out := SecurityView{Findings: []SecFinding{}, Suppressed: []SecFinding{}}
	for _, f := range all {
		if sp, ok := suppByKey[suppressionKey(f.StableID, f.Proto, f.Port)]; ok {
			f.Note, f.SuppressedBy, f.ExpiresAt = sp.Note, sp.SuppressedBy, sp.ExpiresAt
			out.Suppressed = append(out.Suppressed, f)
			continue
		}
		out.Findings = append(out.Findings, f)
	}

	sortFindings(out.Findings)
	sortFindings(out.Suppressed)
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

func sortFindings(fs []SecFinding) {
	rank := map[string]int{"high": 0, "medium": 1, "low": 2}
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if rank[a.Severity] != rank[b.Severity] {
			return rank[a.Severity] < rank[b.Severity]
		}
		if a.Host != b.Host {
			return a.Host < b.Host
		}
		return a.Port < b.Port
	})
}

// suppressRequest acknowledges (accepts the risk of) a security finding so it
// stops counting as active and stops firing alerts, with an optional note. The
// expiry is optional and mutually exclusive: ExpiresInDays > 0 suppresses for
// that many days from now; otherwise ExpiresAt (RFC3339) sets an explicit
// deadline; otherwise the suppression is indefinite.
type suppressRequest struct {
	StableID      string `json:"stable_id"`
	Proto         string `json:"proto"`
	Port          int    `json:"port"`
	Note          string `json:"note"`
	ExpiresInDays int    `json:"expires_in_days,omitempty"`
	ExpiresAt     string `json:"expires_at,omitempty"`
}

func (s *Server) handleSuppressFinding(w http.ResponseWriter, r *http.Request) {
	who, ok := s.requireOperator(w, r)
	if !ok {
		return
	}
	var req suppressRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad JSON")
		return
	}
	if strings.TrimSpace(req.StableID) == "" {
		writeErr(w, http.StatusBadRequest, "stable_id is required")
		return
	}
	now := time.Now().UTC()
	var expires *time.Time
	switch {
	case req.ExpiresInDays > 0:
		t := now.AddDate(0, 0, req.ExpiresInDays)
		expires = &t
	case strings.TrimSpace(req.ExpiresAt) != "":
		t, err := time.Parse(time.RFC3339, strings.TrimSpace(req.ExpiresAt))
		if err != nil {
			writeErr(w, http.StatusBadRequest, "expires_at must be RFC3339")
			return
		}
		if !t.After(now) {
			writeErr(w, http.StatusBadRequest, "expires_at must be in the future")
			return
		}
		t = t.UTC()
		expires = &t
	}
	if err := s.store.SetSecuritySuppression(r.Context(), entity.SecuritySuppression{
		StableID:     req.StableID,
		Proto:        req.Proto,
		Port:         req.Port,
		Note:         strings.TrimSpace(req.Note),
		SuppressedAt: now,
		SuppressedBy: who.username,
		ExpiresAt:    expires,
	}); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.auditf(r.Context(), who, "security.suppress", "%s %s/%d", req.StableID, req.Proto, req.Port)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleUnsuppressFinding(w http.ResponseWriter, r *http.Request) {
	who, ok := s.requireOperator(w, r)
	if !ok {
		return
	}
	var req suppressRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad JSON")
		return
	}
	if err := s.store.DeleteSecuritySuppression(r.Context(), req.StableID, req.Proto, req.Port); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.auditf(r.Context(), who, "security.unsuppress", "%s %s/%d", req.StableID, req.Proto, req.Port)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func hostLabel(h entity.Host) string {
	if h.DisplayName != "" {
		return h.DisplayName
	}
	return h.StableID
}
