package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/breed007/Tessera/internal/account"
	"github.com/breed007/Tessera/internal/entity"
	"github.com/breed007/Tessera/internal/observation"
)

// bulkRequest applies one action to many devices at once (operator; the forget
// action is admin-only). For add_tags, each host's existing tags are preserved
// and the new ones merged in.
type bulkRequest struct {
	StableIDs []string `json:"stable_ids"`
	Action    string   `json:"action"` // expected | ignored | new | add_tags | forget
	Tags      []string `json:"tags,omitempty"`
}

func (s *Server) handleBulk(w http.ResponseWriter, r *http.Request) {
	who, ok := s.requireOperator(w, r)
	if !ok {
		return
	}
	var req bulkRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad JSON")
		return
	}
	if len(req.StableIDs) == 0 {
		writeErr(w, http.StatusBadRequest, "stable_ids is required")
		return
	}
	if len(req.StableIDs) > 2000 {
		writeErr(w, http.StatusBadRequest, "too many devices in one bulk action (max 2000)")
		return
	}
	switch req.Action {
	case "expected", "ignored", "new", "add_tags":
	case "forget":
		// Mass-deleting history is the most destructive lever in the app — it
		// stays behind the admin bar even though single-device Forget doesn't.
		if who.role != account.RoleAdmin {
			writeErr(w, http.StatusForbidden, "bulk forget requires the admin role (a single device can be forgotten by an operator)")
			return
		}
	default:
		writeErr(w, http.StatusBadRequest, "unknown action")
		return
	}
	ctx := r.Context()
	snap, err := s.store.LoadEntities(ctx)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	byStable := map[string]entity.Host{}
	for _, h := range snap.Hosts {
		byStable[h.StableID] = h
	}

	rec := func(sid string, attr observation.Attribute, val string) error {
		st, subj, err := subjectFromStableID(sid)
		if err != nil {
			return err
		}
		_, err = s.sink.Record(ctx, observation.SourceManual, st, subj, attr, val, manualConfidence)
		return err
	}

	addTags := cleanTags(req.Tags)
	affected := 0
	for _, sid := range req.StableIDs {
		h, ok := byStable[sid]
		if !ok {
			continue
		}
		switch req.Action {
		case "expected":
			if rec(sid, observation.AttrIsExpected, "true") == nil && rec(sid, observation.AttrIgnored, "false") == nil {
				affected++
			}
		case "ignored":
			if rec(sid, observation.AttrIgnored, "true") == nil {
				affected++
			}
		case "new":
			if rec(sid, observation.AttrIsExpected, "false") == nil && rec(sid, observation.AttrIgnored, "false") == nil {
				affected++
			}
		case "add_tags":
			if len(addTags) == 0 {
				continue
			}
			if rec(sid, observation.AttrTags, strings.Join(unionTags(h.Tags, addTags), ",")) == nil {
				affected++
			}
		case "forget":
			if _, err := s.store.ForgetSubjects(ctx, sid, snap.SubjectsForHost(h.ID)); err == nil {
				affected++
			}
		}
	}

	s.log.Info("bulk action", "action", req.Action, "requested", len(req.StableIDs), "affected", affected)
	s.auditf(ctx, who, "hosts.bulk", "action=%s affected=%d", req.Action, affected)
	s.reconcileNow(ctx)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "affected": affected})
}

// cleanTags trims, drops empties, and neutralizes the comma storage delimiter.
func cleanTags(tags []string) []string {
	out := make([]string, 0, len(tags))
	for _, t := range tags {
		t = strings.ReplaceAll(strings.TrimSpace(t), ",", " ")
		if t != "" {
			out = append(out, t)
		}
	}
	return out
}

// unionTags merges add into existing, preserving order and dropping duplicates.
func unionTags(existing, add []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, t := range append(append([]string{}, existing...), add...) {
		if t != "" && !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	return out
}
