package api

import (
	"context"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/tessera/tessera/internal/account"
	"github.com/tessera/tessera/internal/collector"
	"github.com/tessera/tessera/internal/config"
	"github.com/tessera/tessera/internal/observation"
	"github.com/tessera/tessera/internal/secret"
	"github.com/tessera/tessera/internal/settings"
	"github.com/tessera/tessera/internal/store/sqlite"
)

func TestSystemEndpoint(t *testing.T) {
	ctx := context.Background()
	dsn := filepath.Join(t.TempDir(), "sys.db")
	st, err := sqlite.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	sink := observation.NewSink("seed", st)
	if _, err := sink.Record(ctx, observation.SourceUniFi, observation.SubjectMAC, "aa:bb:cc:00:00:01", observation.AttrHostname, "router", 90); err != nil {
		t.Fatal(err)
	}

	cipher, _ := secret.New(secret.GenerateKey())
	srv := New(Options{
		ListenAddr: "127.0.0.1:0", Token: testToken, Accounts: account.NewManager(st),
		Settings: settings.New(st, cipher), EffectiveConfig: config.Default(), Store: st,
		DSN:     dsn,
		Version: "0.9.0", Build: "test",
		Dropped:  func() int64 { return 7 },
		Statuses: func() []collector.Status { return []collector.Status{{Name: "unifi", State: "ok", Detail: "polled"}} },
	})
	ts := httptest.NewServer(srv.routes())
	t.Cleanup(ts.Close)

	info := getJSON[SystemInfo](t, ts.URL+"/api/system")
	if info.Version != "0.9.0" || info.Build != "test" {
		t.Errorf("version/build = %q/%q", info.Version, info.Build)
	}
	if info.ObservationsTotal != 1 {
		t.Errorf("observations = %d, want 1", info.ObservationsTotal)
	}
	if info.Dropped != 7 {
		t.Errorf("dropped = %d, want 7 (from the injected counter)", info.Dropped)
	}
	if info.DBSizeBytes <= 0 {
		t.Errorf("db_size_bytes = %d, want > 0", info.DBSizeBytes)
	}
	if len(info.Collectors) != 1 || info.Collectors[0].Name != "unifi" {
		t.Errorf("collectors = %+v", info.Collectors)
	}
}
