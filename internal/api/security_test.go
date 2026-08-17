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

	// The host's own detail surfaces its findings (telnet high + mysql medium).
	hd := getJSON[HostDetail](t, ts.URL+"/api/host?id=mac:aa:bb:cc:00:00:01")
	if hd.SecFindings != 2 || hd.SecHigh != 1 {
		t.Errorf("host detail issues = %d findings / %d high, want 2/1", hd.SecFindings, hd.SecHigh)
	}

	// Suppress the telnet finding → it moves to Suppressed, high count drops to 0.
	if r := authPost(t, ts.URL+"/api/security/suppress", map[string]any{
		"stable_id": "mac:aa:bb:cc:00:00:01", "proto": "tcp", "port": 23, "note": "isolated VLAN",
	}); r.StatusCode != 200 {
		t.Fatalf("suppress → %d", r.StatusCode)
	} else {
		r.Body.Close()
	}
	d2 := getJSON[SecurityView](t, ts.URL+"/api/security")
	if d2.High != 0 || d2.Medium != 1 {
		t.Fatalf("after suppress: high=%d medium=%d, want 0/1: %+v", d2.High, d2.Medium, d2.Findings)
	}
	if len(d2.Suppressed) != 1 || d2.Suppressed[0].Port != 23 || d2.Suppressed[0].Note != "isolated VLAN" {
		t.Fatalf("suppressed list wrong: %+v", d2.Suppressed)
	}

	// Restore it → back to an active finding.
	if r := authPost(t, ts.URL+"/api/security/unsuppress", map[string]any{
		"stable_id": "mac:aa:bb:cc:00:00:01", "proto": "tcp", "port": 23,
	}); r.StatusCode != 200 {
		t.Fatalf("unsuppress → %d", r.StatusCode)
	} else {
		r.Body.Close()
	}
	d3 := getJSON[SecurityView](t, ts.URL+"/api/security")
	if d3.High != 1 || len(d3.Suppressed) != 0 {
		t.Fatalf("after restore: high=%d suppressed=%d, want 1/0", d3.High, len(d3.Suppressed))
	}

	// Timed suppression: 30 days → suppressed now, with an expiry set.
	if r := authPost(t, ts.URL+"/api/security/suppress", map[string]any{
		"stable_id": "mac:aa:bb:cc:00:00:01", "proto": "tcp", "port": 23, "expires_in_days": 30,
	}); r.StatusCode != 200 {
		t.Fatalf("timed suppress → %d", r.StatusCode)
	} else {
		r.Body.Close()
	}
	d4 := getJSON[SecurityView](t, ts.URL+"/api/security")
	if d4.High != 0 || len(d4.Suppressed) != 1 || d4.Suppressed[0].ExpiresAt == nil {
		t.Fatalf("timed suppress: high=%d suppressed=%d expiry=%v, want 0/1/non-nil", d4.High, len(d4.Suppressed), d4.Suppressed[0].ExpiresAt)
	}

	// An already-expired suppression must be ignored (finding resurfaces).
	past := time.Now().UTC().Add(-time.Hour)
	if err := st.SetSecuritySuppression(ctx, entity.SecuritySuppression{
		StableID: "mac:aa:bb:cc:00:00:01", Proto: "tcp", Port: 23, ExpiresAt: &past,
	}); err != nil {
		t.Fatal(err)
	}
	d5 := getJSON[SecurityView](t, ts.URL+"/api/security")
	if d5.High != 1 || len(d5.Suppressed) != 0 {
		t.Fatalf("expired suppress: high=%d suppressed=%d, want 1/0 (resurfaced)", d5.High, len(d5.Suppressed))
	}
}

