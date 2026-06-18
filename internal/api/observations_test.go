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
	"github.com/tessera/tessera/internal/secret"
	"github.com/tessera/tessera/internal/settings"
	"github.com/tessera/tessera/internal/store/sqlite"
)

func TestObservationsFilter(t *testing.T) {
	ctx := context.Background()
	st, err := sqlite.Open(filepath.Join(t.TempDir(), "obs.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	t0 := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	sink := observation.NewSink("seed", st)
	rec := func(src observation.Source, subj string, a observation.Attribute, v string) {
		if _, err := sink.Record(ctx, src, observation.SubjectMAC, subj, a, v, 90, observation.At(t0)); err != nil {
			t.Fatal(err)
		}
	}
	rec(observation.SourceUniFi, "aa:bb:cc:00:00:01", observation.AttrHostname, "router")
	rec(observation.SourceUniFi, "aa:bb:cc:00:00:01", observation.AttrIPBinding, "10.0.0.5")
	rec(observation.SourcePassiveARP, "dd:ee:ff:00:00:02", observation.AttrIPBinding, "10.0.0.9")

	cipher, _ := secret.New(secret.GenerateKey())
	srv := New(Options{
		ListenAddr: "127.0.0.1:0", Token: testToken, Accounts: account.NewManager(st),
		Settings: settings.New(st, cipher), EffectiveConfig: config.Default(), Store: st,
	})
	ts := httptest.NewServer(srv.routes())
	t.Cleanup(ts.Close)

	// No filter: all 3, with facets on the first page.
	all := getJSON[ObservationsPage](t, ts.URL+"/api/observations")
	if all.Total != 3 || len(all.Rows) != 3 {
		t.Fatalf("unfiltered total=%d rows=%d, want 3/3", all.Total, len(all.Rows))
	}
	if len(all.Sources) != 2 {
		t.Errorf("sources facet = %v, want 2 (unifi, passive_arp)", all.Sources)
	}
	// Filter by source.
	uni := getJSON[ObservationsPage](t, ts.URL+"/api/observations?source=unifi")
	if uni.Total != 2 {
		t.Errorf("source=unifi total=%d, want 2", uni.Total)
	}
	// Filter by value substring.
	q := getJSON[ObservationsPage](t, ts.URL+"/api/observations?q=10.0.0.9")
	if q.Total != 1 || q.Rows[0].Value != "10.0.0.9" {
		t.Errorf("q=10.0.0.9 → %+v, want one match", q.Rows)
	}
}
