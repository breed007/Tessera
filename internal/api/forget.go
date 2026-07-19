package api

import (
	"encoding/json"
	"net/http"
	"strings"
)

// forgetRequest deletes all stored history for one device so it can be
// rediscovered fresh (admin-only; destructive).
type forgetRequest struct {
	StableID string `json:"stable_id"`
}

// handleForgetHost wipes a device: its log observations (by MAC/IP subject) plus
// its workflow state (conflict resolutions, security suppressions), then
// reconciles so it drops out of the entity layer. If the device is still on the
// network, the next collector cycle rediscovers it as a new device.
func (s *Server) handleForgetHost(w http.ResponseWriter, r *http.Request) {
	who, ok := s.requireOperator(w, r)
	if !ok {
		return
	}
	var req forgetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad JSON")
		return
	}
	req.StableID = strings.TrimSpace(req.StableID)
	if req.StableID == "" {
		writeErr(w, http.StatusBadRequest, "stable_id is required")
		return
	}
	ctx := r.Context()
	snap, err := s.store.LoadEntities(ctx)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	var subjects []string
	found := false
	for _, h := range snap.Hosts {
		if h.StableID == req.StableID {
			subjects = snap.SubjectsForHost(h.ID)
			found = true
			break
		}
	}
	if !found {
		writeErr(w, http.StatusNotFound, "unknown host")
		return
	}
	removed, err := s.store.ForgetSubjects(ctx, req.StableID, subjects)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.log.Info("device forgotten", "stable_id", req.StableID, "subjects", len(subjects), "observations_removed", removed)
	s.auditf(ctx, who, "host.forget", "%s (%d observations removed)", req.StableID, removed)
	s.reconcileNow(ctx)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "observations_removed": removed})
}
