package api

import (
	"encoding/json"
	"net/http"
	"os"
	"time"
)

// handleSetupStatus tells the UI whether to show the first-run wizard. Always
// public so the SPA can decide between the setup form and the login form.
func (s *Server) handleSetupStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"first_run":      s.firstRun.Load(),
		"token_required": s.setupToken != "",
		"tls":            s.tls.Enabled,
	})
}

// handleSetup completes first-run setup: validate the one-time token, create the
// first admin, then auto-login so the operator goes straight in. Available only
// while unconfigured (closes as soon as an account exists).
func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	if !s.firstRun.Load() {
		writeErr(w, http.StatusGone, "already configured")
		return
	}
	var req struct{ Token, Username, Password string }
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad JSON")
		return
	}
	// A token is required only when one was configured (hardened mode); open
	// first-run (the default) lets the first visitor create the admin.
	if s.setupToken != "" && !ctEqual(req.Token, s.setupToken) {
		writeErr(w, http.StatusUnauthorized, "invalid setup token")
		return
	}
	if err := s.accounts.CreateFirstAdmin(r.Context(), req.Username, req.Password); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.firstRun.Store(false)
	if s.setupFile != "" {
		_ = os.Remove(s.setupFile)
	}
	s.log.Info("first-run setup complete", "admin", req.Username)

	// Auto-login the new admin.
	if token, _, err := s.accounts.Login(r.Context(), req.Username, req.Password); err == nil {
		http.SetCookie(w, &http.Cookie{
			Name: sessionCookie, Value: token, Path: "/", HttpOnly: true,
			Secure: s.tls.Enabled, SameSite: http.SameSiteLaxMode, Expires: time.Now().Add(7 * 24 * time.Hour),
		})
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
