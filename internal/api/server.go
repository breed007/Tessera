// Package api serves the read API (with provenance), the manual-annotation write
// path, and — as of §M10 — multi-user auth, runtime settings, and the embedded
// UI. Static assets are public; /api/* requires a session (login) or an admin
// bearer token. Admin role is required for any write (annotate, settings, users).
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/tessera/tessera/internal/account"
	"github.com/tessera/tessera/internal/collector"
	"github.com/tessera/tessera/internal/config"
	"github.com/tessera/tessera/internal/observation"
	"github.com/tessera/tessera/internal/settings"
	"github.com/tessera/tessera/internal/store"
	"github.com/tessera/tessera/internal/web"
)

// Options configures the API server.
type Options struct {
	ListenAddr     string
	Token          string // optional admin bearer token (automation)
	TLS            TLSOptions
	DataDir        string // where a self-signed cert is cached
	AllowInsecure  bool   // disable auth entirely (open API)
	FirstRun       bool   // no accounts yet → serve token-gated setup
	SetupToken     string // one-time first-run token
	SetupTokenFile string // deleted once setup completes

	Accounts        *account.Manager
	Settings        *settings.Service
	EffectiveConfig config.Config // current effective config (for tests + display)
	Store           store.Store
	Reconcile       func(context.Context) error
	Rescan          func(context.Context, []netip.Addr) error // on-demand active probe of explicit targets
	Statuses        func() []collector.Status                 // collector connection health (UniFi, Fingerbank)
	OnRestart       func()                                    // triggers a graceful restart to apply settings

	Log *slog.Logger
}

// TLSOptions controls HTTPS. When Enabled with no cert/key, a self-signed cert is
// generated and cached in DataDir.
type TLSOptions struct {
	Enabled  bool
	CertFile string
	KeyFile  string
}

// Server is the HTTP(S) server.
type Server struct {
	store         store.Store
	sink          *observation.Sink
	accounts      *account.Manager
	settings      *settings.Service
	cfg           config.Config
	reconcile     func(context.Context) error
	rescan        func(context.Context, []netip.Addr) error
	statuses      func() []collector.Status
	onRestart     func()
	token         string
	tls           TLSOptions
	dataDir       string
	allowInsecure bool
	setupToken    string
	setupFile     string
	log           *slog.Logger
	http          *http.Server

	firstRun       atomic.Bool // unconfigured: serve token-gated setup
	restartPending atomic.Bool // a settings change is awaiting a restart
}

// New builds the API server.
func New(opts Options) *Server {
	log := opts.Log
	if log == nil {
		log = slog.Default()
	}
	s := &Server{
		store:         opts.Store,
		sink:          observation.NewSink("api", opts.Store),
		accounts:      opts.Accounts,
		settings:      opts.Settings,
		cfg:           opts.EffectiveConfig,
		reconcile:     opts.Reconcile,
		rescan:        opts.Rescan,
		statuses:      opts.Statuses,
		onRestart:     opts.OnRestart,
		token:         opts.Token,
		tls:           opts.TLS,
		dataDir:       opts.DataDir,
		allowInsecure: opts.AllowInsecure,
		setupToken:    opts.SetupToken,
		setupFile:     opts.SetupTokenFile,
		log:           log,
	}
	s.firstRun.Store(opts.FirstRun)
	s.http = &http.Server{
		Addr:              opts.ListenAddr,
		Handler:           s.routes(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	return s
}

// CheckBindSecurity refuses an unauthenticated non-loopback bind (§M8/§M10).
func CheckBindSecurity(listenAddr string, authConfigured, allowInsecure bool) error {
	if authConfigured || allowInsecure || isLoopbackAddr(listenAddr) {
		return nil
	}
	return fmt.Errorf("api: refusing to bind %s without auth — run `tessera setup` to create an "+
		"admin account (api.allow_insecure: true overrides)", listenAddr)
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()

	// First-run setup (public only while unconfigured).
	mux.HandleFunc("GET /api/setup/status", s.handleSetupStatus)
	mux.HandleFunc("POST /api/setup", s.handleSetup)

	// Auth / identity.
	mux.HandleFunc("POST /api/login", s.handleLogin)
	mux.HandleFunc("POST /api/logout", s.handleLogout)
	mux.HandleFunc("GET /api/me", s.handleMe)
	mux.HandleFunc("POST /api/me/password", s.handleChangePassword)

	// Read API.
	mux.HandleFunc("GET /api/summary", s.handleSummary)
	mux.HandleFunc("GET /api/hosts", s.handleHosts)
	mux.HandleFunc("GET /api/host", s.handleHost)
	mux.HandleFunc("GET /api/subnets", s.handleSubnets)
	mux.HandleFunc("GET /api/conflicts", s.handleConflicts)
	mux.HandleFunc("GET /api/new", s.handleNewDevices)
	mux.HandleFunc("GET /api/observations", s.handleObservations)
	mux.HandleFunc("GET /api/status", s.handleStatus)

	// Export.
	mux.HandleFunc("GET /api/exports", s.handleExportList)
	mux.HandleFunc("GET /api/export/{name}", s.handleExport)

	// Annotation (admin).
	mux.HandleFunc("POST /api/host/annotate", s.handleAnnotate)
	mux.HandleFunc("POST /api/address/reserve", s.handleReserve)
	mux.HandleFunc("POST /api/host/rescan", s.handleRescanHost)
	mux.HandleFunc("POST /api/subnet/rescan", s.handleRescanSubnet)

	// Settings + users + tests + restart (admin).
	mux.HandleFunc("GET /api/settings", s.handleGetSettings)
	mux.HandleFunc("PUT /api/settings", s.handlePutSettings)
	mux.HandleFunc("GET /api/users", s.handleListUsers)
	mux.HandleFunc("POST /api/users", s.handleCreateUser)
	mux.HandleFunc("PUT /api/users/{id}", s.handleUpdateUser)
	mux.HandleFunc("DELETE /api/users/{id}", s.handleDeleteUser)
	mux.HandleFunc("POST /api/test/unifi", s.handleTestUniFi)
	mux.HandleFunc("POST /api/test/snmp", s.handleTestSNMP)
	mux.HandleFunc("POST /api/test/fingerbank", s.handleTestFingerbank)
	mux.HandleFunc("POST /api/restart", s.handleRestart)

	// Device icons (§M12). Custom icon assets are public like the bundled ones.
	mux.HandleFunc("GET /api/icons", s.handleListIcons)
	mux.HandleFunc("POST /api/icons", s.handleUploadIcon)
	mux.HandleFunc("DELETE /api/icons/{id}", s.handleDeleteIcon)
	mux.HandleFunc("GET /icons/custom/{id}", s.handleCustomIcon)

	mux.Handle("/", web.Handler())

	return logRequests(s.log, s.authGate(mux))
}

// ListenAndServe binds and serves (HTTP or HTTPS) until ctx is cancelled.
func (s *Server) ListenAndServe(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.http.Addr)
	if err != nil {
		if errors.Is(err, syscall.EADDRINUSE) {
			return fmt.Errorf("api: %s is already in use — change api.listen_addr", s.http.Addr)
		}
		return fmt.Errorf("api: listen %s: %w", s.http.Addr, err)
	}

	var serve func() error
	scheme := "http"
	if s.tls.Enabled {
		cert, key, terr := s.ensureTLS()
		if terr != nil {
			_ = ln.Close()
			return terr
		}
		scheme = "https"
		serve = func() error { return s.http.ServeTLS(ln, cert, key) }
	} else {
		serve = func() error { return s.http.Serve(ln) }
	}

	errc := make(chan error, 1)
	go func() {
		s.log.Info("api listening", "addr", s.http.Addr, "scheme", scheme)
		if err := serve(); err != nil && err != http.ErrServerClosed {
			errc <- err
		}
	}()
	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return s.http.Shutdown(shutCtx)
	case err := <-errc:
		return err
	}
}

// ── helpers ──────────────────────────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func contextWithTimeout(r *http.Request, d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(r.Context(), d)
}

func logRequests(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
		log.Debug("api request", "method", r.Method, "path", r.URL.Path)
	})
}
