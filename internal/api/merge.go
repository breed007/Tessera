package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/tessera/tessera/internal/entity"
)

// mergeRequest links two host identities as the same device: secondary folds
// into primary on the next reconcile.
type mergeRequest struct {
	Primary   string `json:"primary"`
	Secondary string `json:"secondary"`
}

func (s *Server) handleMergeHosts(w http.ResponseWriter, r *http.Request) {
	who, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	var req mergeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad JSON")
		return
	}
	req.Primary, req.Secondary = strings.TrimSpace(req.Primary), strings.TrimSpace(req.Secondary)
	if req.Primary == "" || req.Secondary == "" {
		writeErr(w, http.StatusBadRequest, "primary and secondary are required")
		return
	}
	if req.Primary == req.Secondary {
		writeErr(w, http.StatusBadRequest, "cannot merge a host into itself")
		return
	}
	ctx := r.Context()
	existing, err := s.store.ListMerges(ctx)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	// Reject a link that would create a cycle: if the primary already resolves
	// (transitively) to the secondary, linking them back loops.
	if canonicalMerge(mergeMap(existing), req.Primary) == req.Secondary {
		writeErr(w, http.StatusBadRequest, "that merge would create a cycle")
		return
	}
	if err := s.store.SetMerge(ctx, entity.HostMerge{
		Secondary: req.Secondary, Primary: req.Primary,
		CreatedAt: time.Now().UTC(), CreatedBy: who.username,
	}); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.log.Info("hosts merged", "primary", req.Primary, "secondary", req.Secondary)
	s.reconcileNow(ctx)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// unmergeRequest splits a previously-merged identity back out.
type unmergeRequest struct {
	Secondary string `json:"secondary"`
}

func (s *Server) handleUnmergeHost(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}
	var req unmergeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad JSON")
		return
	}
	if err := s.store.DeleteMerge(r.Context(), strings.TrimSpace(req.Secondary)); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.reconcileNow(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func mergeMap(ms []entity.HostMerge) map[string]string {
	m := map[string]string{}
	for _, x := range ms {
		m[x.Secondary] = x.Primary
	}
	return m
}

// canonicalMerge follows merge links from key to its primary (cycle-guarded).
func canonicalMerge(m map[string]string, key string) string {
	seen := map[string]bool{}
	for {
		next, ok := m[key]
		if !ok || next == "" || next == key || seen[key] {
			return key
		}
		seen[key] = true
		key = next
	}
}

// mergedInto returns the secondary stable_ids that resolve (transitively) to the
// given host — i.e. the identities it has absorbed.
func mergedInto(ms []entity.HostMerge, stableID string) []string {
	m := mergeMap(ms)
	var out []string
	for _, x := range ms {
		if canonicalMerge(m, x.Secondary) == stableID {
			out = append(out, x.Secondary)
		}
	}
	return out
}
