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

func TestComputeChanges(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	at := func(min int) time.Time { return t0.Add(time.Duration(min) * time.Minute) }
	o := func(min int, a observation.Attribute, v string) observation.Observation {
		return observation.Observation{ObservedAt: at(min), Attribute: a, Value: v}
	}
	// Newest-first, as ForSubjects returns.
	obs := []observation.Observation{
		o(40, observation.AttrFirmware, "7.5.4"),  // firmware 7.4.1 → 7.5.4
		o(35, observation.AttrOpenPort, "tcp/443"), // new service
		o(30, observation.AttrIPBinding, "10.0.0.7"), // ip 10.0.0.5 → 10.0.0.7
		o(20, observation.AttrFirmware, "7.4.1"),
		o(15, observation.AttrOpenPort, "tcp/22"), // first service
		o(10, observation.AttrIPBinding, "10.0.0.5"),
	}
	got := computeChanges(obs)
	// Newest-first: firmware change, new tcp/443, ip change, first tcp/22. The
	// first firmware/ip observations set a baseline (no emit); every newly-seen
	// port emits a "new service".
	if len(got) != 4 {
		t.Fatalf("got %d changes, want 4: %+v", len(got), got)
	}
	if got[0].Kind != "firmware" || got[0].From != "7.4.1" || got[0].To != "7.5.4" {
		t.Errorf("newest change = %+v, want firmware 7.4.1→7.5.4", got[0])
	}
	var sawService, sawIP bool
	for _, c := range got {
		if c.Kind == "service" && c.To == "tcp/443" {
			sawService = true
		}
		if c.Kind == "ip" && c.From == "10.0.0.5" && c.To == "10.0.0.7" {
			sawIP = true
		}
	}
	if !sawService || !sawIP {
		t.Errorf("missing service/ip change: %+v", got)
	}
}

func TestSubnetDetail(t *testing.T) {
	ctx := context.Background()
	st, err := sqlite.Open(filepath.Join(t.TempDir(), "sn.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	t0 := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	sink := observation.NewSink("seed", st)
	rec := func(sty observation.SubjectType, subj string, a observation.Attribute, v string, c int) {
		if _, err := sink.Record(ctx, observation.SourceUniFi, sty, subj, a, v, c, observation.At(t0)); err != nil {
			t.Fatal(err)
		}
	}
	rec(observation.SubjectIPv4, "10.0.0.0", observation.AttrSubnetHint,
		observation.SubnetHintValue{CIDR: "10.0.0.0/24", Name: "LAN"}.MarshalValue(), 95)
	rec(observation.SubjectMAC, "aa:bb:cc:00:00:01", observation.AttrIPBinding, "10.0.0.20", 90)

	recon := reconcile.New(st, nil, reconcile.Params{Now: func() time.Time { return t0.Add(time.Minute) }})
	if _, err := recon.Rebuild(ctx); err != nil {
		t.Fatal(err)
	}
	cipher, _ := secret.New(secret.GenerateKey())
	srv := New(Options{
		ListenAddr: "127.0.0.1:0", Token: testToken, Accounts: account.NewManager(st),
		Settings: settings.New(st, cipher), EffectiveConfig: config.Default(), Store: st,
	})
	ts := httptest.NewServer(srv.routes())
	t.Cleanup(ts.Close)

	d := getJSON[SubnetDetail](t, ts.URL+"/api/subnet?id=1")
	if !d.FullMap {
		t.Fatalf("/24 should map fully: %+v", d)
	}
	if d.Total < 250 || d.Used != 1 {
		t.Errorf("total=%d used=%d, want ~253 / 1", d.Total, d.Used)
	}
	if d.NextFree == "" || d.NextFree == "10.0.0.20" {
		t.Errorf("next_free = %q, want the first free address", d.NextFree)
	}
}
