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

// TestPortmap builds a switch with a known model (so the full faceplate renders)
// and one client patched into port 3, then checks the port map fills every slot.
func TestPortmap(t *testing.T) {
	ctx := context.Background()
	st, err := sqlite.Open(filepath.Join(t.TempDir(), "ports.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	t0 := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	sink := observation.NewSink("seed", st)
	const sw, cl = "bb:bb:bb:00:00:02", "cc:cc:cc:00:00:03"
	rec := func(subj string, a observation.Attribute, v string) {
		if _, err := sink.Record(ctx, observation.SourceUniFi, observation.SubjectMAC, subj, a, v, 90, observation.At(t0)); err != nil {
			t.Fatal(err)
		}
	}
	rec(sw, observation.AttrIPBinding, "10.0.0.2")
	rec(sw, observation.AttrHostname, "sw")
	rec(sw, observation.AttrModel, "USW Flex 2.5G 5") // 5 physical ports
	rec(cl, observation.AttrIPBinding, "10.0.0.20")
	rec(cl, observation.AttrHostname, "pc")
	rec(cl, observation.AttrSwitchPort, sw+"/3|1000") // client on switch port 3 @ 1G

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

	d := getJSON[PortmapView](t, ts.URL+"/api/portmap")
	if len(d.Switches) != 1 {
		t.Fatalf("switches = %d, want 1", len(d.Switches))
	}
	s := d.Switches[0]
	if s.Name != "sw" || s.Total != 5 || s.Used != 1 {
		t.Errorf("switch = %+v, want sw total=5 used=1", s)
	}
	if len(s.Ports) != 5 {
		t.Fatalf("ports rendered = %d, want 5 (all slots)", len(s.Ports))
	}
	p3 := s.Ports[2]
	if p3.Port != 3 || p3.Device != "pc" || p3.Speed != "1 GbE" {
		t.Errorf("port 3 = %+v, want pc @ 1 GbE", p3)
	}
	if s.Ports[0].Device != "" {
		t.Errorf("port 1 should be empty, got %+v", s.Ports[0])
	}
}
