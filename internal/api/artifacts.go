package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/tessera/tessera/internal/observation"
	"github.com/tessera/tessera/internal/store"
)

// deleteArtifactRequest surgically removes one piece of a device's history — a
// stale address, a MAC/interface, a service/port, or a single observation — by
// deleting the underlying log rows, then reconciling. Admin-only, destructive.
//
// Like Forget, this is a deliberate departure from the append-only log; and like
// Forget, if the artifact is still live on the network a collector re-observes it
// on the next cycle. It's for clearing out *stale* facts that won't re-appear.
type deleteArtifactRequest struct {
	StableID string `json:"stable_id"`
	Kind     string `json:"kind"` // observation | address | interface | service
	ID       int64  `json:"id,omitempty"`
	IP       string `json:"ip,omitempty"`
	MAC      string `json:"mac,omitempty"`
	Proto    string `json:"proto,omitempty"`
	Port     int    `json:"port,omitempty"`
}

func (s *Server) handleDeleteArtifact(w http.ResponseWriter, r *http.Request) {
	who, ok := s.requireOperator(w, r)
	if !ok {
		return
	}
	var req deleteArtifactRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad JSON")
		return
	}
	ctx := r.Context()

	var removed int64
	del := func(f store.ObsDeleteFilter) bool {
		n, err := s.store.DeleteObservations(ctx, f)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return false
		}
		removed += n
		return true
	}

	switch req.Kind {
	case "observation":
		if req.ID <= 0 {
			writeErr(w, http.StatusBadRequest, "id is required")
			return
		}
		n, err := s.store.DeleteObservation(ctx, req.ID)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		removed = n
	case "address":
		ip := strings.TrimSpace(req.IP)
		if ip == "" {
			writeErr(w, http.StatusBadRequest, "ip is required")
			return
		}
		// IP-subject facts (open ports, liveness, reservation, dhcp) + every binding
		// that points a MAC at this IP.
		if !del(store.ObsDeleteFilter{Subject: ip}) {
			return
		}
		if !del(store.ObsDeleteFilter{Attribute: string(observation.AttrIPBinding), Value: ip}) {
			return
		}
	case "interface":
		mac := strings.ToLower(strings.TrimSpace(req.MAC))
		if mac == "" {
			writeErr(w, http.StatusBadRequest, "mac is required")
			return
		}
		if !del(store.ObsDeleteFilter{Subject: mac}) {
			return
		}
	case "service":
		ip := strings.TrimSpace(req.IP)
		if ip == "" || req.Proto == "" || req.Port <= 0 {
			writeErr(w, http.StatusBadRequest, "ip, proto and port are required")
			return
		}
		pp := fmt.Sprintf("%s/%d", req.Proto, req.Port)
		if !del(store.ObsDeleteFilter{Subject: ip, Attribute: string(observation.AttrOpenPort), Value: pp}) {
			return
		}
		// Banners are stored "proto/port|banner" — drop this port's banners too.
		if !del(store.ObsDeleteFilter{Subject: ip, Attribute: string(observation.AttrServiceBanner), ValuePrefix: pp + "|"}) {
			return
		}
	default:
		writeErr(w, http.StatusBadRequest, "unknown kind")
		return
	}

	s.log.Info("artifact deleted", "kind", req.Kind, "stable_id", req.StableID, "observations_removed", removed)
	s.auditf(ctx, who, "host.delete_artifact", "%s kind=%s", req.StableID, req.Kind)
	s.reconcileNow(ctx)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "observations_removed": removed})
}
