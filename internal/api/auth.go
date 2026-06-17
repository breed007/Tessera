package api

import (
	"context"
	"crypto/subtle"
	"net"
	"net/http"
	"strings"

	"github.com/tessera/tessera/internal/account"
)

// §M10 auth: a cookie session (from the login page) OR an admin bearer token
// (for automation). Two roles — admin (everything) and viewer (read-only).
// Static UI assets are public (they hold no data); /api/* requires auth.

const sessionCookie = "tessera_session"

type principal struct {
	username string
	role     account.Role
}

type ctxKey int

const principalKey ctxKey = 1

func principalFrom(ctx context.Context) (principal, bool) {
	p, ok := ctx.Value(principalKey).(principal)
	return p, ok
}

// principal resolves the request's identity from a session cookie or bearer token.
func (s *Server) principal(r *http.Request) (principal, bool) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		if user, role, ok := s.accounts.Session(r.Context(), c.Value); ok {
			return principal{user, role}, true
		}
	}
	if s.token != "" {
		if rest, found := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); found && ctEqual(rest, s.token) {
			return principal{"api-token", account.RoleAdmin}, true
		}
		if ctEqual(r.Header.Get("X-API-Token"), s.token) {
			return principal{"api-token", account.RoleAdmin}, true
		}
	}
	return principal{}, false
}

// publicPath reports whether a path is reachable without authentication: static
// UI, login, and (only while unconfigured) the first-run setup endpoints.
func (s *Server) publicPath(path string) bool {
	if !strings.HasPrefix(path, "/api/") {
		return true // static UI assets (hold no data)
	}
	switch path {
	case "/api/login", "/api/setup/status", "/api/version":
		return true
	case "/api/setup":
		return s.firstRun.Load()
	}
	return false
}

// authGate enforces authentication for non-public /api/* routes. When
// allow_insecure is set, the API is fully open (a deliberate escape hatch).
func (s *Server) authGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.allowInsecure || s.publicPath(r.URL.Path) {
			// Even when open, attach an admin principal so write handlers work.
			if s.allowInsecure {
				next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), principalKey, principal{"insecure", account.RoleAdmin})))
				return
			}
			next.ServeHTTP(w, r)
			return
		}
		p, ok := s.principal(r)
		if !ok {
			writeErr(w, http.StatusUnauthorized, "authentication required")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), principalKey, p)))
	})
}

// requireAdmin writes 403 and returns false if the caller isn't an admin.
func (s *Server) requireAdmin(w http.ResponseWriter, r *http.Request) (principal, bool) {
	p, ok := principalFrom(r.Context())
	if !ok || p.role != account.RoleAdmin {
		writeErr(w, http.StatusForbidden, "admin role required")
		return principal{}, false
	}
	return p, true
}

func ctEqual(got, want string) bool {
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

// isLoopbackAddr reports whether listenAddr binds only the loopback interface.
func isLoopbackAddr(listenAddr string) bool {
	host, _, err := net.SplitHostPort(listenAddr)
	if err != nil {
		host = listenAddr
	}
	switch host {
	case "", "0.0.0.0", "::", "*":
		return false
	case "localhost":
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
