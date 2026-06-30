package api

import (
	"context"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/tessera/tessera/internal/account"
	"github.com/tessera/tessera/internal/config"
	"github.com/tessera/tessera/internal/observation"
	"github.com/tessera/tessera/internal/reconcile"
	"github.com/tessera/tessera/internal/secret"
	"github.com/tessera/tessera/internal/settings"
	"github.com/tessera/tessera/internal/store/sqlite"
)

// setupConflict seeds one host with two disagreeing device_class observations
// (UniFi vs Fingerbank) so reconciliation records a conflict.
func setupConflict(t *testing.T) *httptest.Server {
	t.Helper()
	ctx := context.Background()
	st, err := sqlite.Open(filepath.Join(t.TempDir(), "cf.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	t0 := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	sink := observation.NewSink("seed", st)
	rec := func(src observation.Source, a observation.Attribute, v string, c int) {
		if _, err := sink.Record(ctx, src, observation.SubjectMAC, "aa:bb:cc:00:00:21", a, v, c, observation.At(t0)); err != nil {
			t.Fatal(err)
		}
	}
	rec(observation.SourceUniFi, observation.AttrIPBinding, "10.0.0.30", 90)
	rec(observation.SourceUniFi, observation.AttrDeviceClass, "Ford F-150 Lightning", 75)
	rec(observation.SourceFingerbank, observation.AttrDeviceClass, "Ford F-150 Raptor", 80)

	recon := reconcile.New(st, nil, reconcile.Params{Now: func() time.Time { return t0.Add(time.Minute) }})
	if _, err := recon.Rebuild(ctx); err != nil {
		t.Fatal(err)
	}
	accounts := account.NewManager(st)
	cipher, _ := secret.New(secret.GenerateKey())
	srv := New(Options{
		ListenAddr:      "127.0.0.1:0",
		Token:           testToken,
		Accounts:        accounts,
		Settings:        settings.New(st, cipher),
		EffectiveConfig: config.Default(),
		Store:           st,
		Reconcile:       func(ctx context.Context) error { _, e := recon.Rebuild(ctx); return e },
	})
	ts := httptest.NewServer(srv.routes())
	t.Cleanup(ts.Close)
	return ts
}

type conflictsResp struct {
	Open       []map[string]any `json:"open"`
	Resolved   []map[string]any `json:"resolved"`
	Precedence []map[string]any `json:"precedence"`
}

func TestConflictPrecedence(t *testing.T) {
	ts := setupConflict(t)
	// One open conflict to start (device_class: UniFi vs Fingerbank).
	d := getJSON[conflictsResp](t, ts.URL+"/api/conflicts")
	if len(d.Open) != 1 {
		t.Fatalf("open = %d, want 1", len(d.Open))
	}
	// Set a precedence policy preferring UniFi for device_class.
	r := authPost(t, ts.URL+"/api/conflict/precedence", map[string]any{"attribute": "device_class", "source": "unifi"})
	if r.StatusCode != 200 {
		t.Fatalf("set precedence → %d", r.StatusCode)
	}
	r.Body.Close()
	d2 := getJSON[conflictsResp](t, ts.URL+"/api/conflicts")
	if len(d2.Open) != 0 {
		t.Errorf("after policy, open = %d, want 0 (auto-resolved)", len(d2.Open))
	}
	if len(d2.Precedence) != 1 {
		t.Errorf("precedence rules = %d, want 1", len(d2.Precedence))
	}
	// Clearing the policy reopens the conflict.
	c := authPost(t, ts.URL+"/api/conflict/precedence", map[string]any{"attribute": "device_class", "source": ""})
	c.Body.Close()
	d3 := getJSON[conflictsResp](t, ts.URL+"/api/conflicts")
	if len(d3.Open) != 1 {
		t.Errorf("after clearing policy, open = %d, want 1", len(d3.Open))
	}
}

func TestConflictResolveReopen(t *testing.T) {
	ts := setupConflict(t)

	// One open conflict, nothing resolved yet.
	got := getJSON[conflictsResp](t, ts.URL+"/api/conflicts")
	if len(got.Open) != 1 || len(got.Resolved) != 0 {
		t.Fatalf("initial conflicts = %d open / %d resolved, want 1/0", len(got.Open), len(got.Resolved))
	}
	if sum := getJSON[Summary](t, ts.URL+"/api/summary"); sum.OpenConflicts != 1 {
		t.Errorf("summary open_conflicts = %d, want 1", sum.OpenConflicts)
	}

	// Resolve it: keep "Ford F-150 Raptor" as source of truth.
	r := authPost(t, ts.URL+"/api/conflict/resolve", map[string]any{
		"subject": "mac:aa:bb:cc:00:00:21", "attribute": "device_class",
		"value": "Ford F-150 Raptor", "source": "fingerbank", "note": "it's the Raptor",
	})
	if r.StatusCode != 200 {
		t.Fatalf("resolve → %d, want 200", r.StatusCode)
	}
	r.Body.Close()

	// Now open is empty, one resolved with the chosen value, and the host's
	// device_class reflects the manual choice.
	got = getJSON[conflictsResp](t, ts.URL+"/api/conflicts")
	if len(got.Open) != 0 || len(got.Resolved) != 1 {
		t.Fatalf("after resolve = %d open / %d resolved, want 0/1", len(got.Open), len(got.Resolved))
	}
	if got.Resolved[0]["chosen_value"] != "Ford F-150 Raptor" {
		t.Errorf("resolved chosen_value = %v", got.Resolved[0]["chosen_value"])
	}
	if sum := getJSON[Summary](t, ts.URL+"/api/summary"); sum.OpenConflicts != 0 {
		t.Errorf("summary open_conflicts after resolve = %d, want 0", sum.OpenConflicts)
	}
	detail := getJSON[HostDetail](t, ts.URL+"/api/host?id=mac:aa:bb:cc:00:00:21")
	if detail.Host.DeviceClass != "Ford F-150 Raptor" {
		t.Errorf("host device_class = %q, want the resolved value", detail.Host.DeviceClass)
	}

	// Reopen: back to one open conflict.
	r2 := authPost(t, ts.URL+"/api/conflict/reopen", map[string]any{"subject": "mac:aa:bb:cc:00:00:21", "attribute": "device_class"})
	if r2.StatusCode != 200 {
		t.Fatalf("reopen → %d, want 200", r2.StatusCode)
	}
	r2.Body.Close()
	got = getJSON[conflictsResp](t, ts.URL+"/api/conflicts")
	if len(got.Resolved) != 0 {
		t.Errorf("after reopen resolved = %d, want 0", len(got.Resolved))
	}
}
