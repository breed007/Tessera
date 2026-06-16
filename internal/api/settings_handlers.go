package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/tessera/tessera/internal/account"
	"github.com/tessera/tessera/internal/collector/active"
	"github.com/tessera/tessera/internal/collector/fingerbank"
	"github.com/tessera/tessera/internal/collector/unifi"
	"github.com/tessera/tessera/internal/settings"
)

func (s *Server) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}
	editable, flags, err := s.settings.Current(r.Context(), s.cfg)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"editable":          editable,
		"secrets_set":       flags,
		"can_store_secrets": s.settings.CanStoreSecrets(),
		"restart_pending":   s.restartPending.Load(),
	})
}

func (s *Server) handlePutSettings(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	var req struct {
		Editable settings.Editable     `json:"editable"`
		Secrets  settings.SecretsInput `json:"secrets"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad JSON")
		return
	}
	if err := s.settings.SaveEditable(r.Context(), req.Editable); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if s.settings.CanStoreSecrets() {
		if err := s.settings.SaveSecrets(r.Context(), req.Secrets); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	s.restartPending.Store(true)
	_ = s.accounts.Audit(r.Context(), p.username, "settings.update", "")
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "restart_required": true})
}

// ── users ────────────────────────────────────────────────────────────────────

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}
	users, err := s.accounts.ListUsers(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, users)
}

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	var req struct {
		Username, Password, Role string
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad JSON")
		return
	}
	if err := s.accounts.CreateUser(r.Context(), p.username, req.Username, req.Password, account.Role(req.Role)); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleUpdateUser(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad id")
		return
	}
	var req struct {
		Username, Role, Password string
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad JSON")
		return
	}
	if err := s.accounts.UpdateUser(r.Context(), p.username, id, req.Username, account.Role(req.Role), req.Password); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad id")
		return
	}
	if err := s.accounts.DeleteUser(r.Context(), p.username, id); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// ── connection tests ─────────────────────────────────────────────────────────

func (s *Server) handleTestUniFi(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}
	var req struct {
		BaseURL    string `json:"base_url"`
		PathPrefix string `json:"path_prefix"`
		Site       string `json:"site"`
		Username   string `json:"username"`
		Password   string `json:"password"`
		APIKey     string `json:"api_key"`
		VerifyTLS  bool   `json:"verify_tls"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad JSON")
		return
	}
	ctx, cancel := contextWithTimeout(r, 20*time.Second)
	defer cancel()
	n, err := unifi.Test(ctx, unifi.Config{
		BaseURL: req.BaseURL, PathPrefix: req.PathPrefix, Site: req.Site, VerifyTLS: req.VerifyTLS,
		Auth: unifi.Auth{Username: req.Username, Password: req.Password, APIKey: req.APIKey},
	})
	testResult(w, fmtTestUniFi(n), err)
}

func (s *Server) handleTestSNMP(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}
	var req struct {
		IP        string `json:"ip"`
		Community string `json:"community"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad JSON")
		return
	}
	ctx, cancel := contextWithTimeout(r, 5*time.Second)
	defer cancel()
	name, err := active.TestSNMP(ctx, req.IP, req.Community)
	testResult(w, "sysName: "+name, err)
}

func (s *Server) handleTestFingerbank(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}
	var req struct {
		Key string `json:"key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad JSON")
		return
	}
	ctx, cancel := contextWithTimeout(r, 15*time.Second)
	defer cancel()
	testResult(w, "API key accepted", fingerbank.TestKey(ctx, req.Key))
}

func (s *Server) handleRestart(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	_ = s.accounts.Audit(r.Context(), p.username, "restart", "")
	writeJSON(w, http.StatusOK, map[string]string{"status": "restarting"})
	if s.onRestart != nil {
		go func() { time.Sleep(300 * time.Millisecond); s.onRestart() }()
	}
}

func testResult(w http.ResponseWriter, ok string, err error) {
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "detail": ok})
}

func fmtTestUniFi(n int) string { return "connected; " + strconv.Itoa(n) + " clients visible" }
