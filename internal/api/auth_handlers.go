package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/breed007/Tessera/internal/account"
)

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct{ Username, Password string }
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad JSON")
		return
	}
	token, u, err := s.accounts.Login(r.Context(), req.Username, req.Password)
	if err != nil {
		if errors.Is(err, account.ErrInvalidCredentials) {
			writeErr(w, http.StatusUnauthorized, "invalid username or password")
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.tls.Enabled,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(7 * 24 * time.Hour),
	})
	writeJSON(w, http.StatusOK, map[string]string{"username": u.Username, "role": string(u.Role)})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		_ = s.accounts.Logout(r.Context(), c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", HttpOnly: true, MaxAge: -1})
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{
		"username":          p.username,
		"role":              string(p.role),
		"is_admin":          p.role == account.RoleAdmin,
		"can_edit":          account.CanEdit(p.role), // admin or operator: may curate inventory
		"can_store_secrets": s.settings.CanStoreSecrets(),
		"tls":               s.tls.Enabled,
	})
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	p, ok := principalFrom(r.Context())
	if !ok || p.username == "api-token" {
		writeErr(w, http.StatusForbidden, "not a user session")
		return
	}
	var req struct{ Current, New string }
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad JSON")
		return
	}
	if err := s.accounts.ChangePassword(r.Context(), p.username, req.Current, req.New); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
