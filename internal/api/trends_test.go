package api

import (
	"context"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/breed007/Tessera/internal/account"
	"github.com/breed007/Tessera/internal/config"
	"github.com/breed007/Tessera/internal/entity"
	"github.com/breed007/Tessera/internal/observation"
	"github.com/breed007/Tessera/internal/reconcile"
	"github.com/breed007/Tessera/internal/secret"
	"github.com/breed007/Tessera/internal/settings"
	"github.com/breed007/Tessera/internal/store/sqlite"
)

func TestTrends(t *testing.T) {
	ctx := context.Background()
	st, err := sqlite.Open(filepath.Join(t.TempDir(), "tr.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	t0 := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	sink := observation.NewSink("seed", st)
	rec := func(sty observation.SubjectType, subj string, a observation.Attribute, v string, at time.Time) {
		if _, err := sink.Record(ctx, observation.SourceUniFi, sty, subj, a, v, 95, observation.At(at)); err != nil {
			t.Fatal(err)
		}
	}
	rec(observation.SubjectIPv4, "10.0.0.0", observation.AttrSubnetHint, observation.SubnetHintValue{CIDR: "10.0.0.0/24"}.MarshalValue(), t0)
	rec(observation.SubjectMAC, "aa:bb:cc:00:00:01", observation.AttrIPBinding, "10.0.0.5", t0)
	rec(observation.SubjectMAC, "aa:bb:cc:00:00:02", observation.AttrIPBinding, "10.0.0.6", t0.Add(48*time.Hour))

	recon := reconcile.New(st, nil, reconcile.Params{Now: func() time.Time { return t0.Add(72 * time.Hour) }})
	if _, err := recon.Rebuild(ctx); err != nil {
		t.Fatal(err)
	}
	if err := st.AppendAvailability(ctx, []entity.AvailabilityEvent{
		{StableID: "mac:aa:bb:cc:00:00:01", Online: true, At: t0},
		{StableID: "mac:aa:bb:cc:00:00:02", Online: true, At: t0.Add(24 * time.Hour)},
		{StableID: "mac:aa:bb:cc:00:00:01", Online: false, At: t0.Add(48 * time.Hour)},
	}); err != nil {
		t.Fatal(err)
	}
	cipher, _ := secret.New(secret.GenerateKey())
	srv := New(Options{
		ListenAddr: "127.0.0.1:0", Token: testToken, Accounts: account.NewManager(st),
		Settings: settings.New(st, cipher), EffectiveConfig: config.Default(), Store: st,
	})
	ts := httptest.NewServer(srv.routes())
	t.Cleanup(ts.Close)

	d := getJSON[TrendsView](t, ts.URL+"/api/trends")
	// Device growth: two distinct first-seen days → cumulative 1, then 2.
	if len(d.DeviceGrowth) != 2 || d.DeviceGrowth[0].V != 1 || d.DeviceGrowth[1].V != 2 {
		t.Fatalf("device_growth = %+v, want cumulative [1,2]", d.DeviceGrowth)
	}
	// Availability timeline ends at online=1 (h1 went offline last).
	if n := len(d.Availability); n == 0 || d.Availability[n-1].V != 1 {
		t.Fatalf("availability = %+v, want last online=1", d.Availability)
	}
	// Subnet utilization: both host IPs land in the /24 → 2 used of 254 usable.
	if len(d.Subnets) != 1 || d.Subnets[0].Used != 2 || d.Subnets[0].Total != 254 {
		t.Fatalf("subnets = %+v, want 2 used / 254", d.Subnets)
	}
}
