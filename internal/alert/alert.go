// Package alert detects reconciliation deltas and does two things with them.
// After each rebuild it diffs the entity snapshot against the previously-seen
// state and, on a transition (not every cycle, so it can't flap):
//
//   - ALWAYS persists the change to the append-only event history (the Activity
//     feed + the incremental-sync cursor for API consumers), independent of
//     whether webhook alerting is configured; and
//   - dispatches the operator-enabled subset to a webhook (generic JSON, Slack,
//     Discord, or ntfy) when alerting is on.
//
// The very first run seeds a silent baseline so existing devices neither fire
// alerts nor flood the history all at once.
package alert

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/tessera/tessera/internal/entity"
	"github.com/tessera/tessera/internal/portrisk"
)

// Event types.
const (
	TypeNewDevice    = "new_device"
	TypeOffline      = "device_offline"
	TypeOnline       = "device_online"
	TypeIPChanged    = "ip_changed"
	TypeConflict     = "conflict"
	TypeRiskyService = "risky_service"
)

const stateKey = "alert.state"

// Event is one notification-worthy change.
type Event struct {
	Type    string    `json:"type"`
	Title   string    `json:"title"`
	Message string    `json:"message"`
	Subject string    `json:"subject"`
	At      time.Time `json:"at"`
	Old     string    `json:"old,omitempty"` // prior value where meaningful (e.g. old IP)
	New     string    `json:"new,omitempty"` // new value
}

// Config is the alerting configuration (assembled from settings + the secret URL).
type Config struct {
	Enabled   bool
	Kind      string // webhook | slack | discord | ntfy
	URL       string // destination (webhook/ntfy topic URL); secret-sourced
	NewDevice    bool
	Offline      bool
	Online       bool
	IPChanged    bool
	Conflict     bool
	RiskyService bool
}

func (c Config) wants(t string) bool {
	switch t {
	case TypeNewDevice:
		return c.NewDevice
	case TypeOffline:
		return c.Offline
	case TypeOnline:
		return c.Online
	case TypeIPChanged:
		return c.IPChanged
	case TypeConflict:
		return c.Conflict
	case TypeRiskyService:
		return c.RiskyService
	}
	return false
}

// Store is the narrow persistence the engine needs.
type Store interface {
	LoadEntities(ctx context.Context) (entity.Snapshot, error)
	SettingGet(ctx context.Context, key string) (string, bool, error)
	SettingSet(ctx context.Context, key, value string, isSecret bool) error
	ListSecuritySuppressions(ctx context.Context) ([]entity.SecuritySuppression, error)
	AppendEvents(ctx context.Context, events []entity.Event) error
}

// Engine diffs snapshots and dispatches alerts.
type Engine struct {
	store Store
	cfg   Config
	log   *slog.Logger
	httpc *http.Client
}

func New(store Store, cfg Config, log *slog.Logger) *Engine {
	if log == nil {
		log = slog.Default()
	}
	return &Engine{store: store, cfg: cfg, log: log, httpc: &http.Client{Timeout: 10 * time.Second}}
}

type hostState struct {
	Online bool   `json:"online"`
	IP     string `json:"ip"`
}

type state struct {
	Hosts     map[string]hostState `json:"hosts"`
	Conflicts map[string]bool      `json:"conflicts"`
	Risky     map[string]bool      `json:"risky"` // "<stable_id>\x1f<proto>/<port>" seen risky services
}

// Process diffs the current entity layer against the last-seen state, persists
// every detected change to the event history, and dispatches the enabled subset
// to the webhook when alerting is configured. Detection always runs so the
// Activity feed works even with alerting off.
func (e *Engine) Process(ctx context.Context) error {
	snap, err := e.store.LoadEntities(ctx)
	if err != nil {
		return err
	}
	prev, firstRun, err := e.loadState(ctx)
	if err != nil {
		return err
	}
	// Operator-suppressed (accepted-risk) findings don't fire risky-service alerts.
	supps, err := e.store.ListSecuritySuppressions(ctx)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	suppressed := map[string]bool{}
	for _, sp := range supps {
		if sp.Active(now) { // expired suppressions don't apply (the finding re-alerts)
			suppressed[fmt.Sprintf("%s\x1f%s/%d", sp.StableID, sp.Proto, sp.Port)] = true
		}
	}

	// Index addresses by host so we can compute online + primary IP.
	type acc struct {
		online bool
		ip     string
	}
	byHost := map[int64]*acc{}
	for _, a := range snap.Addresses {
		if a.HostID == nil {
			continue
		}
		h := byHost[*a.HostID]
		if h == nil {
			h = &acc{}
			byHost[*a.HostID] = h
		}
		active := a.State == entity.StateActive
		if active && (h.ip == "" || !h.online) {
			h.ip = a.IP // prefer an active address as the primary
		} else if h.ip == "" {
			h.ip = a.IP
		}
		if active {
			h.online = true
		}
	}

	cur := state{Hosts: map[string]hostState{}, Conflicts: map[string]bool{}, Risky: map[string]bool{}}
	hostByID := map[int64]entity.Host{}
	for _, h := range snap.Hosts {
		hostByID[h.ID] = h
	}
	var events []Event
	for _, host := range snap.Hosts {
		a := byHost[host.ID]
		hs := hostState{}
		if a != nil {
			hs = hostState{Online: a.online, IP: a.ip}
		}
		cur.Hosts[host.StableID] = hs
		if firstRun {
			continue
		}
		old, known := prev.Hosts[host.StableID]
		name := host.DisplayName
		if name == "" {
			name = host.StableID
		}
		switch {
		case !known:
			if !host.IsExpected && !host.Ignored {
				events = append(events, Event{TypeNewDevice, "New device", fmt.Sprintf("🆕 New device: %s%s%s", name, ipSuffix(hs.IP), descSuffix(host)), host.StableID, host.FirstSeen, "", ""})
			}
		default:
			if old.Online && !hs.Online {
				events = append(events, Event{TypeOffline, "Device offline", fmt.Sprintf("🔴 Offline: %s%s", name, ipSuffix(old.IP)), host.StableID, time.Now(), "online", "offline"})
			} else if !old.Online && hs.Online {
				events = append(events, Event{TypeOnline, "Device online", fmt.Sprintf("🟢 Back online: %s%s", name, ipSuffix(hs.IP)), host.StableID, time.Now(), "offline", "online"})
			}
			if old.IP != "" && hs.IP != "" && old.IP != hs.IP {
				events = append(events, Event{TypeIPChanged, "IP changed", fmt.Sprintf("🔀 %s: IP changed %s → %s", name, old.IP, hs.IP), host.StableID, time.Now(), old.IP, hs.IP})
			}
		}
	}

	for _, c := range snap.Conflicts {
		key := c.Subject + "\x1f" + c.Attribute
		cur.Conflicts[key] = true
		if !firstRun && !prev.Conflicts[key] {
			events = append(events, Event{TypeConflict, "Conflict", fmt.Sprintf("⚠️ Conflict on %s · %s: %q vs %q", c.Subject, c.Attribute, c.ValueA, c.ValueB), c.Subject, time.Now(), c.ValueA, c.ValueB})
		}
	}

	for _, sv := range snap.Services {
		if sv.HostID == nil {
			continue
		}
		host, ok := hostByID[*sv.HostID]
		if !ok || host.Ignored {
			continue
		}
		risk, risky := portrisk.Classify(sv.Port)
		if !risky {
			continue
		}
		key := fmt.Sprintf("%s\x1f%s/%d", host.StableID, sv.Proto, sv.Port)
		if suppressed[key] {
			continue // operator accepted this risk — don't track or alert (unsuppress re-surfaces it)
		}
		cur.Risky[key] = true
		if !firstRun && !prev.Risky[key] {
			name := host.DisplayName
			if name == "" {
				name = host.StableID
			}
			ip := ""
			if a := byHost[host.ID]; a != nil {
				ip = a.ip
			}
			events = append(events, Event{TypeRiskyService, "Risky service",
				fmt.Sprintf("🛡️ %s on %s%s: %s/%d — %s", risk.Severity, name, ipSuffix(ip), sv.Proto, sv.Port, risk.Why), host.StableID, time.Now(), "", fmt.Sprintf("%s/%d", sv.Proto, sv.Port)})
		}
	}

	if !firstRun && len(events) > 0 {
		// Deterministic order so a burst reads sensibly.
		sort.SliceStable(events, func(i, j int) bool { return events[i].Type < events[j].Type })

		// Always record the change history (Activity feed + consumer sync), even
		// when webhook alerting is off.
		if err := e.store.AppendEvents(ctx, toEntityEvents(events)); err != nil {
			e.log.Warn("event history persist failed", "err", err)
		}

		// Dispatch the enabled subset to the webhook, when configured.
		if e.cfg.Enabled && strings.TrimSpace(e.cfg.URL) != "" {
			dispatched := 0
			for _, ev := range events {
				if !e.cfg.wants(ev.Type) {
					continue
				}
				if err := Notify(ctx, e.httpc, e.cfg.Kind, e.cfg.URL, ev); err != nil {
					e.log.Warn("alert dispatch failed", "type", ev.Type, "err", err)
				}
				dispatched++
			}
			if dispatched > 0 {
				e.log.Info("alerts dispatched", "count", dispatched)
			}
		}
	}
	return e.saveState(ctx, cur)
}

func (e *Engine) loadState(ctx context.Context) (state, bool, error) {
	v, ok, err := e.store.SettingGet(ctx, stateKey)
	if err != nil {
		return state{}, false, err
	}
	if !ok || v == "" {
		return state{Hosts: map[string]hostState{}, Conflicts: map[string]bool{}}, true, nil
	}
	var s state
	if err := json.Unmarshal([]byte(v), &s); err != nil {
		// Corrupt state → reseed silently rather than spam.
		return state{Hosts: map[string]hostState{}, Conflicts: map[string]bool{}}, true, nil
	}
	if s.Hosts == nil {
		s.Hosts = map[string]hostState{}
	}
	if s.Conflicts == nil {
		s.Conflicts = map[string]bool{}
	}
	if s.Risky == nil {
		s.Risky = map[string]bool{}
	}
	return s, false, nil
}

func (e *Engine) saveState(ctx context.Context, s state) error {
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return e.store.SettingSet(ctx, stateKey, string(b), false)
}

// toEntityEvents maps detected alert events to the persisted change-history shape.
func toEntityEvents(evs []Event) []entity.Event {
	out := make([]entity.Event, 0, len(evs))
	for _, e := range evs {
		out = append(out, entity.Event{At: e.At, Kind: e.Type, StableID: e.Subject, Message: e.Message, Old: e.Old, New: e.New})
	}
	return out
}

func ipSuffix(ip string) string {
	if ip == "" {
		return ""
	}
	return " (" + ip + ")"
}

func descSuffix(h entity.Host) string {
	d := h.Model
	if d == "" {
		d = h.DeviceClass
	}
	if d == "" {
		return ""
	}
	return " — " + d
}

// Notify formats and sends one event to the destination, shaped per kind.
func Notify(ctx context.Context, httpc *http.Client, kind, url string, ev Event) error {
	if httpc == nil {
		httpc = &http.Client{Timeout: 10 * time.Second}
	}
	var (
		body        []byte
		contentType = "application/json"
		headers     = map[string]string{}
	)
	switch kind {
	case "slack":
		body, _ = json.Marshal(map[string]string{"text": ev.Message})
	case "discord":
		body, _ = json.Marshal(map[string]string{"content": ev.Message})
	case "ntfy":
		body = []byte(ev.Message)
		contentType = "text/plain"
		headers["Title"] = "Tessera — " + ev.Title
	default: // generic webhook
		body, _ = json.Marshal(ev)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", contentType)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := httpc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode >= 300 {
		return fmt.Errorf("alert endpoint returned %d", resp.StatusCode)
	}
	return nil
}
