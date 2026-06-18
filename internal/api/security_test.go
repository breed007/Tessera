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

func TestSecurityFindings(t *testing.T) {
	ctx := context.Background()
	st, err := sqlite.Open(filepath.Join(t.TempDir(), "sec.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	t0 := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	sink := observation.NewSink("seed", st)
	rec := func(sty observation.SubjectType, subj string, a observation.Attribute, v string) {
		if _, err := sink.Record(ctx, observation.SourceActiveTCP, sty, subj, a, v, 75, observation.At(t0)); err != nil {
			t.Fatal(err)
		}
	}
	rec(observation.SubjectMAC, "aa:bb:cc:00:00:01", observation.AttrIPBinding, "10.0.0.5")
	rec(observation.SubjectMAC, "aa:bb:cc:00:00:01", observation.AttrHostname, "nas")
	rec(observation.SubjectIPv4, "10.0.0.5", observation.AttrOpenPort, "tcp/23")   // telnet → high
	rec(observation.SubjectIPv4, "10.0.0.5", observation.AttrOpenPort, "tcp/3306") // mysql → medium
	rec(observation.SubjectIPv4, "10.0.0.5", observation.AttrOpenPort, "tcp/22")   // ssh → not flagged
	rec(observation.SubjectIPv4, "10.0.0.5", observation.AttrOpenPort, "tcp/443")  // https → not flagged

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

	d := getJSON[SecurityView](t, ts.URL+"/api/security")
	if d.High != 1 || d.Medium != 1 {
		t.Fatalf("counts high=%d medium=%d, want 1/1 (telnet high, mysql medium): %+v", d.High, d.Medium, d.Findings)
	}
	var sawTelnet bool
	for _, f := range d.Findings {
		if f.Port == 22 || f.Port == 443 {
			t.Errorf("ssh/https should not be flagged: %+v", f)
		}
		if f.Port == 23 && f.Severity == "high" {
			sawTelnet = true
		}
	}
	if !sawTelnet {
		t.Errorf("telnet (high) finding missing: %+v", d.Findings)
	}
}

