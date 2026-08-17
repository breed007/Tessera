package api

import (
	"context"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/breed007/Tessera/internal/account"
	"github.com/breed007/Tessera/internal/config"
	"github.com/breed007/Tessera/internal/observation"
	"github.com/breed007/Tessera/internal/reconcile"
	"github.com/breed007/Tessera/internal/secret"
	"github.com/breed007/Tessera/internal/settings"
	"github.com/breed007/Tessera/internal/store/sqlite"
)

func TestTopology(t *testing.T) {
	ctx := context.Background()
	st, err := sqlite.Open(filepath.Join(t.TempDir(), "topo.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	t0 := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	sink := observation.NewSink("seed", st)
	const gw, sw, cl = "aa:aa:aa:00:00:01", "bb:bb:bb:00:00:02", "cc:cc:cc:00:00:03"
	rec := func(subj string, a observation.Attribute, v string) {
		if _, err := sink.Record(ctx, observation.SourceUniFi, observation.SubjectMAC, subj, a, v, 90, observation.At(t0)); err != nil {
			t.Fatal(err)
		}
	}
	rec(gw, observation.AttrIPBinding, "10.0.0.1")
	rec(gw, observation.AttrHostname, "udm")
	rec(sw, observation.AttrIPBinding, "10.0.0.2")
	rec(sw, observation.AttrHostname, "sw")
	rec(sw, observation.AttrSwitchPort, gw+"/5|10000") // switch uplinks to gateway port 5 @ 10G
	rec(cl, observation.AttrIPBinding, "10.0.0.20")
	rec(cl, observation.AttrHostname, "pc")
	rec(cl, observation.AttrSwitchPort, sw+"/3") // client on switch port 3

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

	d := getJSON[TopologyView](t, ts.URL+"/api/topology")
	if len(d.Roots) != 1 || d.Roots[0].Name != "udm" {
		t.Fatalf("roots = %+v, want one 'udm'", d.Roots)
	}
	if len(d.Roots[0].Children) != 1 {
		t.Fatalf("gateway children = %d, want 1 (the switch)", len(d.Roots[0].Children))
	}
	swNode := d.Roots[0].Children[0]
	if swNode.Name != "sw" || swNode.Port != "5" || swNode.Speed != "10 GbE" {
		t.Errorf("switch node = %+v, want sw/port5/10 GbE", swNode)
	}
	if len(swNode.Children) != 1 || swNode.Children[0].Name != "pc" || swNode.Children[0].Port != "3" {
		t.Errorf("client under switch wrong: %+v", swNode.Children)
	}
}
