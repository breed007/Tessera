package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/tessera/tessera/internal/entity"
	"github.com/tessera/tessera/internal/observation"
)

// resolveConflictRequest records which value an operator keeps as source of truth
// for a (subject, attribute) conflict, with an optional note.
type resolveConflictRequest struct {
	Subject   string `json:"subject"`
	Attribute string `json:"attribute"`
	Value     string `json:"value"`  // the chosen source-of-truth value
	Source    string `json:"source"` // which side it came from (for display)
	Note      string `json:"note"`
}

// handleResolveConflict writes the chosen value as an authoritative manual
// annotation (so it wins reconciliation) and records the resolution, then
// reconciles. Admin-only.
func (s *Server) handleResolveConflict(w http.ResponseWriter, r *http.Request) {
	who, ok := s.requireOperator(w, r)
	if !ok {
		return
	}
	var req resolveConflictRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad JSON")
		return
	}
	req.Subject, req.Attribute = strings.TrimSpace(req.Subject), strings.TrimSpace(req.Attribute)
	if req.Subject == "" || req.Attribute == "" {
		writeErr(w, http.StatusBadRequest, "subject and attribute are required")
		return
	}
	if !observation.IsValidAttribute(observation.Attribute(req.Attribute)) {
		writeErr(w, http.StatusBadRequest, "unknown attribute")
		return
	}
	subjectType, subject, err := subjectFromStableID(req.Subject)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	ctx := r.Context()

	// Make the chosen value the source of truth: a manual annotation outranks any
	// discovered value (§3.2). Skip if no value was supplied (acknowledge-only).
	if req.Value != "" {
		if _, err := s.sink.Record(ctx, observation.SourceManual, subjectType, subject,
			observation.Attribute(req.Attribute), req.Value, manualConfidence); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	if err := s.store.SetResolution(ctx, entity.ConflictResolution{
		Subject:      req.Subject,
		Attribute:    req.Attribute,
		ChosenValue:  req.Value,
		ChosenSource: req.Source,
		Note:         strings.TrimSpace(req.Note),
		ResolvedAt:   time.Now().UTC(),
		ResolvedBy:   who.username,
	}); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if s.reconcile != nil {
		if err := s.reconcile(ctx); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	s.auditf(ctx, who, "conflict.resolve", "%s · %s → %q", req.Subject, req.Attribute, req.Value)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// reopenConflictRequest re-opens a resolved conflict (clears the resolution flag;
// any manual value already written stays until re-annotated).
type reopenConflictRequest struct {
	Subject   string `json:"subject"`
	Attribute string `json:"attribute"`
}

// precedenceRequest sets (or, with an empty source, clears) the preferred source
// for an attribute — a policy that resolves a whole class of conflicts at once.
type precedenceRequest struct {
	Attribute string `json:"attribute"`
	Source    string `json:"source"`
}

func (s *Server) handleSetPrecedence(w http.ResponseWriter, r *http.Request) {
	who, ok := s.requireOperator(w, r)
	if !ok {
		return
	}
	var req precedenceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad JSON")
		return
	}
	req.Attribute, req.Source = strings.TrimSpace(req.Attribute), strings.TrimSpace(req.Source)
	if req.Attribute == "" {
		writeErr(w, http.StatusBadRequest, "attribute is required")
		return
	}
	ctx := r.Context()
	if req.Source == "" {
		if err := s.store.DeletePrecedence(ctx, req.Attribute); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
	} else if err := s.store.SetPrecedence(ctx, entity.SourcePrecedence{
		Attribute: req.Attribute, Source: req.Source, CreatedAt: time.Now().UTC(), CreatedBy: who.username,
	}); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.auditf(ctx, who, "conflict.precedence", "%s → %s", req.Attribute, req.Source)
	s.reconcileNow(ctx)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleReopenConflict(w http.ResponseWriter, r *http.Request) {
	who, ok := s.requireOperator(w, r)
	if !ok {
		return
	}
	var req reopenConflictRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad JSON")
		return
	}
	if err := s.store.DeleteResolution(r.Context(), strings.TrimSpace(req.Subject), strings.TrimSpace(req.Attribute)); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.auditf(r.Context(), who, "conflict.reopen", "%s · %s", req.Subject, req.Attribute)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
