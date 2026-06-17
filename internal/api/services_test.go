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

func setupServices(t *testing.T) *httptest.Server {
	t.Helper()
	ctx := context.Background()
	st, err := sqlite.Open(filepath.Join(t.TempDir(), "svc.db"))
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
		if _, err := sink.Record(ctx, observation.SourceActiveTCP, sty, subj, a, v, c, observation.At(t0)); err != nil {
			t.Fatal(err)
		}
	}
	rec(observation.SubjectMAC, "aa:bb:cc:00:11:22", observation.AttrIPBinding, "10.0.0.30", 90)
	rec(observation.SubjectIPv4, "10.0.0.30", observation.AttrOpenPort, "tcp/9999", 75) // unnamed
	rec(observation.SubjectIPv4, "10.0.0.30", observation.AttrOpenPort, "tcp/443", 75)  // HTTPS
	rec(observation.SubjectIPv4, "10.0.0.30", observation.AttrOpenPort, "tcp/22", 75)   // SSH

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
	return ts
}

func TestServicesSorted(t *testing.T) {
	ts := setupServices(t)
	rows := getJSON[[]ServiceRow](t, ts.URL+"/api/services")
	if len(rows) != 3 {
		t.Fatalf("got %d services, want 3", len(rows))
	}
	// Named services alphabetical (HTTPS, SSH), then the unnamed numeric port.
	if rows[0].Service != "HTTPS" || rows[1].Service != "SSH" {
		t.Errorf("named order wrong: %q, %q", rows[0].Service, rows[1].Service)
	}
	if rows[2].Service != "" || rows[2].Port != 9999 {
		t.Errorf("unnamed port should sort last: %+v", rows[2])
	}
}

func TestServicePortName(t *testing.T) {
	for port, want := range map[int]string{443: "HTTPS", 22: "SSH", 53: "DNS", 12345: ""} {
		if got := servicePortName("tcp", port); got != want {
			t.Errorf("port %d = %q, want %q", port, got, want)
		}
	}
}
