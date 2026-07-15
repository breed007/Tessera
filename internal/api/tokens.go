package api

import (
	_ "embed"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/tessera/tessera/internal/account"
)

//go:embed openapi.json
var openAPISpec []byte

// handleOpenAPI serves the API contract (the shape only — no data), so consumers
// can generate clients. Public.
func (s *Server) handleOpenAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(openAPISpec)
}

// handleListTokens returns the API tokens (metadata only — never the secret).
func (s *Server) handleListTokens(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}
	toks, err := s.accounts.ListAPITokens(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if toks == nil {
		toks = []account.APIToken{}
	}
	writeJSON(w, http.StatusOK, toks)
}

// handleCreateToken mints a named API token and returns the plaintext ONCE.
func (s *Server) handleCreateToken(w http.ResponseWriter, r *http.Request) {
	who, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	var req struct {
		Name string `json:"name"`
		Role string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad JSON")
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		writeErr(w, http.StatusBadRequest, "name is required")
		return
	}
	role := account.Role(req.Role)
	if role == "" {
		role = account.RoleViewer // default consumers to read-only
	}
	if !account.ValidRole(role) {
		writeErr(w, http.StatusBadRequest, "role must be admin or viewer")
		return
	}
	plaintext, t, err := s.accounts.CreateAPIToken(r.Context(), req.Name, role, who.username)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id": t.ID, "name": t.Name, "role": t.Role, "token": plaintext,
	})
}

// handleDeleteToken revokes an API token.
func (s *Server) handleDeleteToken(w http.ResponseWriter, r *http.Request) {
	who, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad id")
		return
	}
	if err := s.accounts.DeleteAPIToken(r.Context(), who.username, id); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
