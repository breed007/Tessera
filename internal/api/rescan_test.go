package api

import (
	"context"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/breed007/Tessera/internal/account"
	"github.com/breed007/Tessera/internal/collector"
	"github.com/breed007/Tessera/internal/config"
	"github.com/breed007/Tessera/internal/observation"
	"github.com/breed007/Tessera/internal/reconcile"
	"github.com/breed007/Tessera/internal/secret"
	"github.com/breed007/Tessera/internal/settings"
	"github.com/breed007/Tessera/internal/store/sqlite"
)

// setupRescan builds a server whose Rescan hook records the probed targets, and
// seeds one host (with an address) on subnet 10.0.0.0/24.
func setupRescan(t *testing.T) (*httptest.Server, func() [][]netip.Addr) {
	t.Helper()
	ctx := context.Background()
	st, err := sqlite.Open(filepath.Join(t.TempDir(), "rescan.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}

	t0 := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	sink := observation.NewSink("seed", st)
	rec := func(src observation.Source, sty observation.SubjectType, subj string, a observation.Attribute, v string, c int) {
		if _, err := sink.Record(ctx, src, sty, subj, a, v, c, observation.At(t0)); err != nil {
			t.Fatal(err)
		}
	}
	rec(observation.SourcePassiveARP, observation.SubjectMAC, "b8:27:eb:11:22:33", observation.AttrIPBinding, "10.0.0.20", 95)
	rec(observation.SourceUniFi, observation.SubjectIPv4, "10.0.0.0", observation.AttrSubnetHint,
		observation.SubnetHintValue{CIDR: "10.0.0.0/24"}.MarshalValue(), 95)

	recon := reconcile.New(st, nil, reconcile.Params{Now: func() time.Time { return t0.Add(time.Minute) }})
	if _, err := recon.Rebuild(ctx); err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	var calls [][]netip.Addr
	done := make(chan struct{}, 4)
	rescan := func(_ context.Context, targets []netip.Addr) error {
		mu.Lock()
		calls = append(calls, targets)
		mu.Unlock()
		done <- struct{}{}
		return nil
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
		Rescan:          rescan,
		Statuses:        func() []collector.Status { return []collector.Status{{Name: "unifi", State: "ok", Detail: "polled"}} },
	})
	ts := httptest.NewServer(srv.routes())
	t.Cleanup(ts.Close)

	getCalls := func() [][]netip.Addr {
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
		mu.Lock()
		defer mu.Unlock()
		out := make([][]netip.Addr, len(calls))
		copy(out, calls)
		return out
	}
	return ts, getCalls
}

func TestRescanHost(t *testing.T) {
	ts, getCalls := setupRescan(t)
	r := authPost(t, ts.URL+"/api/host/rescan", map[string]any{"stable_id": "mac:b8:27:eb:11:22:33"})
	defer r.Body.Close()
	if r.StatusCode != 200 {
		t.Fatalf("rescan host → %d, want 200", r.StatusCode)
	}
	calls := getCalls()
	if len(calls) != 1 || len(calls[0]) != 1 || calls[0][0].String() != "10.0.0.20" {
		t.Fatalf("rescan probed %v, want [[10.0.0.20]]", calls)
	}
}

func TestStatusEndpoint(t *testing.T) {
	ts, _ := setupRescan(t)
	got := getJSON[[]collector.Status](t, ts.URL+"/api/status")
	if len(got) != 1 || got[0].Name != "unifi" || got[0].State != "ok" {
		t.Fatalf("status = %+v, want one ok unifi", got)
	}
}

func TestRescanHostUnknown(t *testing.T) {
	ts, _ := setupRescan(t)
	r := authPost(t, ts.URL+"/api/host/rescan", map[string]any{"stable_id": "mac:00:00:00:00:00:00"})
	defer r.Body.Close()
	if r.StatusCode != 404 {
		t.Errorf("unknown host → %d, want 404", r.StatusCode)
	}
}

func TestRescanSubnet(t *testing.T) {
	ts, getCalls := setupRescan(t)
	r := authPost(t, ts.URL+"/api/subnet/rescan", map[string]any{"subnet_id": 1})
	defer r.Body.Close()
	if r.StatusCode != 202 {
		t.Fatalf("rescan subnet → %d, want 202 (async)", r.StatusCode)
	}
	// The background probe runs the whole /24's host range.
	calls := getCalls()
	if len(calls) != 1 || len(calls[0]) < 250 {
		t.Fatalf("subnet rescan probed %d targets in %d call(s), want one call of ~254", func() int {
			if len(calls) > 0 {
				return len(calls[0])
			}
			return 0
		}(), len(calls))
	}
}

