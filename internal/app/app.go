// Package app wires Tessera's pieces together and runs the daemon lifecycle:
// open storage, migrate, start the enabled collectors, and run the reconcile
// loop until the context is cancelled, then shut down cleanly.
package app

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"sync"
	"time"

	"path/filepath"

	"github.com/breed007/Tessera/internal/account"
	"github.com/breed007/Tessera/internal/alert"
	"github.com/breed007/Tessera/internal/api"
	"github.com/breed007/Tessera/internal/collector"
	"github.com/breed007/Tessera/internal/collector/active"
	"github.com/breed007/Tessera/internal/collector/dhcp"
	"github.com/breed007/Tessera/internal/collector/dns"
	"github.com/breed007/Tessera/internal/collector/fingerbank"
	"github.com/breed007/Tessera/internal/collector/passive"
	"github.com/breed007/Tessera/internal/collector/proxmox"
	"github.com/breed007/Tessera/internal/collector/unifi"
	"github.com/breed007/Tessera/internal/config"
	"github.com/breed007/Tessera/internal/entity"
	"github.com/breed007/Tessera/internal/observation"
	"github.com/breed007/Tessera/internal/reconcile"
	"github.com/breed007/Tessera/internal/secret"
	"github.com/breed007/Tessera/internal/settings"
	"github.com/breed007/Tessera/internal/store"
	"github.com/breed007/Tessera/internal/store/sqlite"
)

// Version (marketing) and Build (YYYY.MM.DD.HH.mm stamp) are set by main from its
// ldflag-injected values, then surfaced to the UI footer via the API.
var (
	Version = "1.0.1"
	Build   = "dev"
)

// App holds the wired-up daemon.
type App struct {
	cfg        config.Config // effective config (file + DB settings overlay)
	log        *slog.Logger
	store      store.Store
	recon      *reconcile.Reconciler
	collectors []collector.Collector
	api        *api.Server
	obsBuf     *observation.BufferedAppender // backpressure-tolerant collector write path
	restart    func()                        // triggers a graceful restart (set by main)
	rescanMu   sync.Mutex                    // serializes on-demand (UI) rescans
	alerts     *alert.Engine                 // dispatches notifications on reconcile deltas
}

// New builds the App: opens the store, applies DB settings over the file config,
// bootstraps the admin user, and constructs the enabled collectors from the
// EFFECTIVE config. The caller owns the lifecycle via Run/Close.
func New(ctx context.Context, fileCfg config.Config, log *slog.Logger) (*App, error) {
	// A staged restore (uploaded via the UI) is swapped in before the DB opens.
	if fileCfg.Storage.Driver == "sqlite" {
		applyPendingRestore(fileCfg.Storage.DSN, log)
	}
	st, err := openStore(fileCfg)
	if err != nil {
		return nil, err
	}
	if err := st.Migrate(ctx); err != nil {
		_ = st.Close()
		return nil, fmt.Errorf("app: migrate: %w", err)
	}
	log.Info("storage ready", "driver", fileCfg.Storage.Driver, "dsn", fileCfg.Storage.DSN)

	dataDir := filepath.Dir(fileCfg.Storage.DSN)

	// Secrets cipher: use the env key, or load/create a persisted one (§M11).
	masterKey := fileCfg.Secrets.SecretKey
	if masterKey == "" {
		if masterKey, err = loadOrCreateMasterKey(dataDir); err != nil {
			_ = st.Close()
			return nil, err
		}
	}
	cipher, err := secret.New(masterKey)
	if err != nil {
		_ = st.Close()
		return nil, fmt.Errorf("app: secret key: %w", err)
	}
	settingsSvc := settings.New(st, cipher)
	cfg, err := settingsSvc.Effective(ctx, fileCfg)
	if err != nil {
		_ = st.Close()
		return nil, fmt.Errorf("app: load settings: %w", err)
	}

	// Bootstrap the first admin account from the file/env credentials.
	accounts := account.NewManager(st)
	if err := accounts.EnsureBootstrapAdmin(ctx, cfg.API.AuthUser, cfg.Secrets.APIPasswordHash); err != nil {
		_ = st.Close()
		return nil, fmt.Errorf("app: bootstrap admin: %w", err)
	}
	nUsers, _ := st.CountUsers(ctx)
	authConfigured := cfg.Secrets.APIToken != "" || nUsers > 0

	// First-run mode: no accounts yet → serve the token-gated setup wizard. The
	// token requires host access, so a LAN bind is safe even while unconfigured.
	firstRun := !authConfigured && !cfg.API.AllowInsecure
	var setupToken, setupTokenFile string
	if firstRun {
		if cfg.API.RequireSetupToken {
			// Hardened: completing setup needs a one-time token (host access).
			if setupToken, setupTokenFile, err = newSetupToken(dataDir); err != nil {
				_ = st.Close()
				return nil, err
			}
			log.Warn("FIRST-RUN SETUP — browse to the UI and enter the setup token",
				"token", setupToken, "token_file", setupTokenFile)
		} else {
			// Open first-run (default): first person to reach the UI is the admin.
			log.Warn("FIRST-RUN SETUP — browse to the UI to create your admin account", "addr", cfg.API.ListenAddr)
		}
	}

	collectors, err := buildCollectors(cfg, st, log)
	if err != nil {
		_ = st.Close()
		return nil, err
	}

	a := &App{
		cfg:        cfg,
		log:        log,
		store:      st,
		collectors: collectors,
		obsBuf:     observation.NewBufferedAppender(st, 8192, log),
		recon: reconcile.New(st, log, reconcile.Params{
			StaleAfter:         cfg.Reconcile.StaleAfter,
			FreeAfter:          cfg.Reconcile.FreeAfter,
			ConfidenceHalfLife: cfg.Reconcile.ConfidenceHalfLife,
		}),
		alerts: alert.New(st, alert.Config{
			Enabled: cfg.Alerts.Enabled, Kind: cfg.Alerts.Kind, URL: cfg.Secrets.AlertWebhookURL,
			NewDevice: cfg.Alerts.NewDevice, Offline: cfg.Alerts.Offline, Online: cfg.Alerts.Online,
			IPChanged: cfg.Alerts.IPChanged, Conflict: cfg.Alerts.Conflict, RiskyService: cfg.Alerts.RiskyService,
		}, log),
	}

	if cfg.API.Enabled {
		// Bind is permitted when auth is configured OR we're in token-gated
		// first-run OR auth is explicitly disabled (§M8/§M11).
		if err := api.CheckBindSecurity(cfg.API.ListenAddr, authConfigured || firstRun, cfg.API.AllowInsecure); err != nil {
			_ = st.Close()
			return nil, err
		}
		a.api = api.New(api.Options{
			ListenAddr:      cfg.API.ListenAddr,
			Token:           cfg.Secrets.APIToken,
			TLS:             api.TLSOptions{Enabled: cfg.API.TLS, CertFile: cfg.API.TLSCertFile, KeyFile: cfg.API.TLSKeyFile},
			DataDir:         dataDir,
			DSN:             cfg.Storage.DSN,
			AllowInsecure:   cfg.API.AllowInsecure,
			FirstRun:        firstRun,
			SetupToken:      setupToken,
			SetupTokenFile:  setupTokenFile,
			Accounts:        accounts,
			Settings:        settingsSvc,
			EffectiveConfig: cfg,
			Store:           st,
			Reconcile:       func(ctx context.Context) error { _, e := a.recon.Rebuild(ctx); return e },
			Rescan:          a.Rescan,
			Statuses:        a.Statuses,
			Dropped:         func() int64 { return a.obsBuf.Dropped() },
			Version:         Version,
			Build:           Build,
			OnRestart:       a.requestRestart,
			Log:             log,
		})
	}

	return a, nil
}

// SetRestart provides the callback that triggers a graceful restart (main wires
// it to the run-context cancel; the process then exits and systemd restarts it).
func (a *App) SetRestart(fn func()) { a.restart = fn }

func (a *App) requestRestart() {
	a.log.Info("restart requested (applying settings)")
	if a.restart != nil {
		a.restart()
	}
}

// buildCollectors constructs the enabled collectors. Secrets come from
// cfg.Secrets (env-sourced); they are passed to the collector and never logged.
func buildCollectors(cfg config.Config, st store.Store, log *slog.Logger) ([]collector.Collector, error) {
	var cs []collector.Collector
	disc := cfg.Discovery.Resolve()

	if cfg.Sensor.Enabled && len(cfg.Sensor.Sources) > 0 {
		sources := make([]passive.CaptureConfig, 0, len(cfg.Sensor.Sources))
		for _, src := range cfg.Sensor.Sources {
			sources = append(sources, passive.CaptureConfig{
				Kind:        src.Kind,
				NIC:         src.NIC,
				BPF:         src.BPF,
				SnapLen:     65535,
				Promiscuous: true,
			})
		}
		dedupe := time.Duration(cfg.Sensor.DedupeWindowMS) * time.Millisecond
		protocols := passive.Protocols{
			ARP: disc.PassiveARP, DHCP: disc.PassiveDHCP, MDNS: disc.PassiveMDNS,
			SSDP: disc.PassiveSSDP, NetBIOS: disc.PassiveNetBIOS,
		}
		s := passive.NewSensor(sources, dedupe, protocols, log)
		cs = append(cs, s)
		log.Info("collector enabled", "name", s.Name(), "sources", len(sources))
	}

	if cfg.ActiveProbe.Enabled {
		// config validation already guarantees subnets are explicit (§4.2).
		p := active.NewProber(activeProbeConfig(cfg), log)
		cs = append(cs, p)
		log.Info("collector enabled", "name", p.Name(),
			"subnets", len(cfg.ActiveProbe.Subnets), "cycle", cfg.ActiveProbe.Rate.CycleInterval)
	}

	if cfg.UniFi.Enabled {
		p, err := unifi.NewPoller(unifi.Config{
			BaseURL:    cfg.UniFi.BaseURL,
			PathPrefix: cfg.UniFi.PathPrefix,
			Site:       cfg.UniFi.Site,
			VerifyTLS:  cfg.UniFi.VerifyTLS,
			Auth: unifi.Auth{
				Username: cfg.Secrets.UniFiUsername,
				Password: cfg.Secrets.UniFiPassword,
				APIKey:   cfg.Secrets.UniFiAPIKey,
			},
		}, cfg.UniFi.PollInterval, log)
		if err != nil {
			return nil, fmt.Errorf("app: build unifi poller: %w", err)
		}
		cs = append(cs, p)
		log.Info("collector enabled", "name", p.Name(), "poll_interval", cfg.UniFi.PollInterval)
	}

	if cfg.DHCP.Enabled && len(cfg.DHCP.LeaseFiles) > 0 {
		d := dhcp.New(dhcp.Config{Files: cfg.DHCP.LeaseFiles, Interval: cfg.DHCP.Interval})
		cs = append(cs, d)
		log.Info("collector enabled", "name", d.Name(), "lease_files", len(cfg.DHCP.LeaseFiles))
	}

	if cfg.DNS.Enabled && (len(cfg.DNS.HostsFiles) > 0 || cfg.DNS.ServerURL != "") {
		d := dns.New(dns.Config{
			HostsFiles: cfg.DNS.HostsFiles,
			ServerType: cfg.DNS.ServerType, ServerURL: cfg.DNS.ServerURL,
			ServerUser: cfg.DNS.ServerUser, ServerToken: cfg.Secrets.DNSServerToken, Interval: cfg.DNS.Interval,
		})
		cs = append(cs, d)
		log.Info("collector enabled", "name", d.Name(), "hosts_files", len(cfg.DNS.HostsFiles), "server", cfg.DNS.ServerType)
	}

	if cfg.Proxmox.Enabled {
		for i, inst := range cfg.Proxmox.Instances {
			if inst.BaseURL == "" || i >= config.MaxProxmoxInstances {
				continue
			}
			auth := proxmox.Auth{}
			if inst.AuthMode == "password" {
				auth.Username, auth.Password = inst.Username, cfg.Secrets.ProxmoxPasswords[i]
			} else {
				auth.Token = cfg.Secrets.ProxmoxTokens[i]
			}
			// Health name is index-based so it's ALWAYS unique — user labels can
			// collide (two "prod" instances) and must not merge two pollers into
			// one status badge. The label is display-only (shown in the UI header).
			name := "proxmox"
			if i > 0 {
				name = fmt.Sprintf("proxmox:%d", i+1)
			}
			px := proxmox.NewPoller(name, proxmox.Config{
				BaseURL: inst.BaseURL, VerifyTLS: inst.VerifyTLS, Auth: auth,
			}, cfg.Proxmox.PollInterval, log)
			cs = append(cs, px)
			log.Info("collector enabled", "name", px.Name(), "label", inst.Name, "base_url", inst.BaseURL, "auth", inst.AuthMode)
		}
	}

	// Fingerbank is privacy-relevant and OFF by default (§7): only built when
	// explicitly enabled with a non-off mode.
	if cfg.Fingerbank.Enabled && cfg.Fingerbank.Mode != "off" && cfg.Fingerbank.Mode != "" {
		enricher, err := buildEnricher(cfg)
		if err != nil {
			return nil, err
		}
		fb := fingerbank.NewCollector(enricher, st, time.Minute, log)
		cs = append(cs, fb)
		log.Info("collector enabled", "name", fb.Name(), "mode", cfg.Fingerbank.Mode)
	}

	return cs, nil
}

// activeProbeConfig builds the active prober's Config from the effective config.
// Shared by the scheduled collector and the on-demand Rescan path; the Discovery
// toggles are authoritative for which techniques run (.WithTechniques).
func activeProbeConfig(cfg config.Config) active.Config {
	disc := cfg.Discovery.Resolve()
	// SNMP communities: the visible, editable list plus the legacy single community
	// (env TESSERA_SNMP_COMMUNITY / older DB secret), de-duplicated, so existing
	// installs keep working while operators manage multiple visibly.
	communities := append([]string(nil), cfg.ActiveProbe.SNMPCommunities...)
	if c := cfg.Secrets.SNMPCommunity; c != "" {
		dup := false
		for _, e := range communities {
			if e == c {
				dup = true
				break
			}
		}
		if !dup {
			communities = append(communities, c)
		}
	}
	return active.Config{
		Subnets:         cfg.ActiveProbe.Subnets,
		TCPPorts:        cfg.ActiveProbe.TCPPorts,
		UDPPorts:        cfg.ActiveProbe.UDPPorts,
		ICMP:            disc.ActiveICMP,
		TCP:             disc.ActiveTCP,
		UDP:             disc.ActiveUDP,
		Banners:         disc.ActiveBanners,
		ReverseDNS:      disc.ActiveReverseDNS,
		ARPTable:        disc.ActiveARPTable,
		SNMP:            disc.ActiveSNMP,
		MDNS:            disc.ActiveMDNS,
		Media:           disc.ActiveMedia,
		NTLM:            disc.ActiveNTLM,
		Proxmox:         disc.ActiveProxmox,
		ESPHome:         disc.ActiveESPHome,
		TCPBehavioral:   disc.TCPBehavioral,
		ThoroughWake:    disc.ThoroughWake,
		SNMPCommunities: communities,
		MaxProbesPerSec: cfg.ActiveProbe.Rate.MaxProbesPerSec,
		CycleInterval:   cfg.ActiveProbe.Rate.CycleInterval,
		Interface:       cfg.ActiveProbe.Interface,
	}.WithTechniques()
}

// Statuses returns the connection health of every collector that reports it
// (UniFi, Fingerbank) — surfaced in the Settings UI.
func (a *App) Statuses() []collector.Status {
	var out []collector.Status
	for _, c := range a.collectors {
		if r, ok := c.(collector.Reporter); ok {
			out = append(out, r.Status())
		}
	}
	return out
}

// Rescan probes the given addresses once on demand (the UI "Rescan" action) and
// rebuilds the entity layer so the result is immediately visible. It uses a
// one-shot prober built from the effective config, so it works even when the
// scheduled active sweep is disabled. Serialized: concurrent rescans queue
// rather than multiplying the probe rate.
func (a *App) Rescan(ctx context.Context, targets []netip.Addr) error {
	a.rescanMu.Lock()
	defer a.rescanMu.Unlock()

	p := active.NewProber(activeProbeConfig(a.cfg), a.log)
	sink := observation.NewSink("active", a.obsBuf)
	p.ProbeOnce(ctx, targets, sink)
	_, err := a.recon.Rebuild(ctx)
	return err
}

// buildEnricher constructs the Fingerbank enricher for the configured mode. The
// API key (api mode) comes from the environment and is never logged.
func buildEnricher(cfg config.Config) (fingerbank.Enricher, error) {
	switch cfg.Fingerbank.Mode {
	case "api":
		return fingerbank.NewAPI(fingerbank.APIConfig{
			Key:        cfg.Secrets.FingerbankKey,
			MaxPerHour: cfg.Fingerbank.Rate.MaxPerHour,
			Burst:      cfg.Fingerbank.Rate.Burst,
			CacheTTL:   cfg.Fingerbank.CacheTTL,
		})
	case "local_db":
		return fingerbank.NewLocalDB(cfg.Fingerbank.DBPath)
	default:
		return fingerbank.NewOff(), nil
	}
}

// openStore builds the configured storage driver behind the store.Store seam.
// openStore returns the concrete *sqlite.Store, which satisfies store.Store plus
// the account.Store and settings.Store capability interfaces used by §M10.
// applyPendingRestore swaps in a database staged by the restore endpoint
// (<dsn>.restore) before the store opens. It validates the staged file by
// opening it and checking the schema; an invalid file is discarded so a bad
// upload can never replace a working database. The replaced DB is kept as
// <dsn>.prev for one generation.
func applyPendingRestore(dsn string, log *slog.Logger) {
	restore := dsn + ".restore"
	if _, err := os.Stat(restore); err != nil {
		return // nothing staged
	}
	// Validate: it must open and have the core schema.
	if vst, err := sqlite.Open(restore); err != nil {
		log.Error("restore rejected — cannot open staged database", "err", err)
		_ = os.Remove(restore)
		return
	} else {
		_, qErr := vst.CountObservations(context.Background())
		_ = vst.Close()
		if qErr != nil {
			log.Error("restore rejected — staged database is not a Tessera DB", "err", qErr)
			_ = os.Remove(restore)
			_ = os.Remove(restore + "-wal")
			_ = os.Remove(restore + "-shm")
			return
		}
	}
	// Swap: drop the live DB + its WAL/SHM, then move the staged file into place.
	for _, sfx := range []string{"", "-wal", "-shm"} {
		_ = os.Remove(dsn + sfx)
	}
	_ = os.Remove(restore + "-wal")
	_ = os.Remove(restore + "-shm")
	if err := os.Rename(restore, dsn); err != nil {
		log.Error("restore failed — could not swap database into place", "err", err)
		return
	}
	log.Warn("database restored from staged backup", "dsn", dsn)
}

func openStore(cfg config.Config) (*sqlite.Store, error) {
	switch cfg.Storage.Driver {
	case "sqlite":
		return sqlite.Open(cfg.Storage.DSN)
	default:
		return nil, fmt.Errorf("app: unsupported storage driver %q", cfg.Storage.Driver)
	}
}

// Store exposes the underlying store (used by the demo/CLI subcommands).
func (a *App) Store() store.Store { return a.store }

// Reconciler exposes the reconciler (used by the demo/CLI subcommands).
func (a *App) Reconciler() *reconcile.Reconciler { return a.recon }

// Run starts the collectors (each in its own panic-recovering goroutine) and
// then periodically rebuilds the entity layer from the log until ctx is
// cancelled, after which it waits for the collectors to stop.
func (a *App) Run(ctx context.Context) error {
	a.log.Info("tessera running", "collectors", len(a.collectors), "reconcile_interval", reconcileInterval)

	var wg sync.WaitGroup

	// The buffered writer drains collector observations into the store; it flushes
	// remaining buffered rows on shutdown (ctx cancel) before returning.
	wg.Add(1)
	go func() {
		defer wg.Done()
		a.obsBuf.Run(ctx)
	}()

	for _, c := range a.collectors {
		wg.Add(1)
		go func(c collector.Collector) {
			defer wg.Done()
			a.runCollector(ctx, c)
		}(c)
	}

	if a.api != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := a.api.ListenAndServe(ctx); err != nil {
				a.log.Error("api server stopped with error", "err", err)
			}
		}()
	}

	// Periodic log compaction bounds the append-only log's growth (§M9).
	if iv := a.cfg.Reconcile.CompactInterval; iv > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a.compactLoop(ctx, iv)
		}()
	}

	// Auto-prune: forget devices not seen for N days (opt-in; destructive).
	if a.cfg.Reconcile.ForgetDormantEnabled && a.cfg.Reconcile.ForgetDormantDays > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a.pruneLoop(ctx, a.cfg.Reconcile.ForgetDormantDays)
		}()
	}

	// Initial reconcile so entities reflect whatever is already in the log. This
	// also seeds the alert baseline silently (so existing devices don't all fire).
	if _, err := a.recon.Rebuild(ctx); err != nil {
		a.log.Error("initial reconcile failed", "err", err)
	}
	a.trackAvailability(ctx)
	a.processAlerts(ctx)

	ticker := time.NewTicker(reconcileInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			a.log.Info("shutdown signal received, stopping collectors")
			wg.Wait()
			return nil
		case <-ticker.C:
			if _, err := a.recon.Rebuild(ctx); err != nil {
				a.log.Error("reconcile failed", "err", err)
			}
			a.trackAvailability(ctx)
			a.processAlerts(ctx)
		}
	}
}

// processAlerts dispatches notifications for the latest reconcile delta. Failures
// never disrupt the loop.
func (a *App) processAlerts(ctx context.Context) {
	if a.alerts == nil {
		return
	}
	if err := a.alerts.Process(ctx); err != nil && ctx.Err() == nil {
		a.log.Warn("alert processing failed", "err", err)
	}
}

// compactLoop periodically collapses repeated observations so the append-only
// log doesn't grow without bound (pollers re-emit identical facts every cycle).
func (a *App) compactLoop(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if n, err := a.store.CompactLog(ctx); err != nil {
				a.log.Error("log compaction failed", "err", err)
			} else if n > 0 {
				a.log.Info("log compacted", "rows_removed", n)
			}
			// Bound the change-history table the same way (keep the most recent N).
			if n, err := a.store.PruneEvents(ctx, maxEvents); err != nil {
				a.log.Error("event prune failed", "err", err)
			} else if n > 0 {
				a.log.Info("events pruned", "rows_removed", n)
			}
		}
	}
}

// maxEvents caps the change-history table. Events are low-frequency (one row per
// transition), so this holds a deep history while still bounding disk on an
// instance that runs for years.
const maxEvents = 20000

// trackAvailability records an online/offline transition whenever a host's
// reachability flips (online = at least one active address). Runs after every
// reconcile; the table only grows on actual transitions. Uses the same
// "active address" definition as the alerts and metrics, so they stay consistent.
func (a *App) trackAvailability(ctx context.Context) {
	snap, err := a.store.LoadEntities(ctx)
	if err != nil {
		a.log.Error("availability: load entities failed", "err", err)
		return
	}
	last, err := a.store.LatestAvailability(ctx)
	if err != nil {
		a.log.Error("availability: latest lookup failed", "err", err)
		return
	}
	online := map[int64]bool{}
	for _, ad := range snap.Addresses {
		if ad.HostID != nil && ad.State == entity.StateActive {
			online[*ad.HostID] = true
		}
	}
	now := time.Now().UTC()
	var evs []entity.AvailabilityEvent
	for _, h := range snap.Hosts {
		cur := online[h.ID]
		if prev, known := last[h.StableID]; !known || prev != cur {
			evs = append(evs, entity.AvailabilityEvent{StableID: h.StableID, Online: cur, At: now})
		}
	}
	if err := a.store.AppendAvailability(ctx, evs); err != nil {
		a.log.Error("availability: append failed", "err", err)
	}
}

// pruneLoop periodically forgets devices that haven't been seen on the network
// for the configured number of days (decommissioned hardware, deleted VMs). It
// runs once shortly after start, then hourly (the window is in days, so a coarse
// cadence is plenty).
func (a *App) pruneLoop(ctx context.Context, days int) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	a.pruneDormant(ctx, days)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			a.pruneDormant(ctx, days)
		}
	}
}

// pruneDormant forgets each host whose newest network observation is older than
// the cutoff. Hosts with no discovery observations (manual/user-created entries)
// are never auto-pruned.
func (a *App) pruneDormant(ctx context.Context, days int) {
	cutoff := time.Now().Add(-time.Duration(days) * 24 * time.Hour)
	lastSeen, err := a.store.LastSeenBySubject(ctx)
	if err != nil {
		a.log.Error("auto-prune: last-seen lookup failed", "err", err)
		return
	}
	snap, err := a.store.LoadEntities(ctx)
	if err != nil {
		a.log.Error("auto-prune: load entities failed", "err", err)
		return
	}
	pruned := 0
	for _, h := range snap.Hosts {
		subjects := snap.SubjectsForHost(h.ID)
		var newest time.Time
		seenOnNetwork := false
		for _, sub := range subjects {
			if ts, ok := lastSeen[sub]; ok {
				seenOnNetwork = true
				if ts.After(newest) {
					newest = ts
				}
			}
		}
		if !seenOnNetwork || !newest.Before(cutoff) {
			continue // never observed by a collector, or seen recently
		}
		if _, err := a.store.ForgetSubjects(ctx, h.StableID, subjects); err != nil {
			a.log.Error("auto-prune: forget failed", "stable_id", h.StableID, "err", err)
			continue
		}
		a.log.Info("auto-pruned dormant device", "stable_id", h.StableID, "last_seen", newest.Format(time.RFC3339), "dormant_days", days)
		pruned++
	}
	if pruned > 0 {
		if _, err := a.recon.Rebuild(ctx); err != nil {
			a.log.Error("auto-prune: reconcile failed", "err", err)
		}
	}
}

// runCollector runs one collector with its own Sink, recovering any panic at the
// goroutine boundary (§10: no panic crosses into the app).
func (a *App) runCollector(ctx context.Context, c collector.Collector) {
	defer func() {
		if r := recover(); r != nil {
			a.log.Error("collector panicked (recovered)", "name", c.Name(), "panic", r)
		}
	}()
	sink := observation.NewSink(c.Name(), a.obsBuf)
	if err := c.Run(ctx, sink); err != nil && ctx.Err() == nil {
		a.log.Error("collector stopped with error", "name", c.Name(), "err", err)
	}
}

// Close releases resources. Safe to call once after Run returns.
func (a *App) Close() error {
	a.log.Info("closing storage")
	return a.store.Close()
}

// reconcileInterval is the M1 fixed cadence for full rebuilds. M2 makes this
// incremental and config-driven.
const reconcileInterval = 30 * time.Second
