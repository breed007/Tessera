package api

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
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

func TestMetricsExposition(t *testing.T) {
	ctx := context.Background()
	st, err := sqlite.Open(filepath.Join(t.TempDir(), "m.db"))
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
	rec(observation.SourceUniFi, observation.SubjectIPv4, "10.0.0.0", observation.AttrSubnetHint,
		observation.SubnetHintValue{CIDR: "10.0.0.0/24"}.MarshalValue(), 95)
	rec(observation.SourcePassiveARP, observation.SubjectMAC, "aa:bb:cc:00:00:01", observation.AttrIPBinding, "10.0.0.5", 95)
	rec(observation.SourceActiveTCP, observation.SubjectIPv4, "10.0.0.5", observation.AttrOpenPort, "tcp/23", 80) // telnet → high

	recon := reconcile.New(st, nil, reconcile.Params{Now: func() time.Time { return t0.Add(time.Minute) }})
	if _, err := recon.Rebuild(ctx); err != nil {
		t.Fatal(err)
	}
	cipher, _ := secret.New(secret.GenerateKey())
	srv := New(Options{
		ListenAddr: "127.0.0.1:0", Token: testToken, Accounts: account.NewManager(st),
		Settings: settings.New(st, cipher), EffectiveConfig: config.Default(), Store: st,
		Version: "0.9.0", Build: "2026.01.01.12.00",
		Statuses: func() []collector.Status {
			return []collector.Status{{Name: "unifi", State: "ok", LastRun: t0}}
		},
	})
	ts := httptest.NewServer(srv.routes())
	t.Cleanup(ts.Close)

	r := authGet(t, ts.URL+"/api/metrics")
	defer r.Body.Close()
	if r.StatusCode != 200 {
		t.Fatalf("GET metrics → %d", r.StatusCode)
	}
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("content-type = %q, want text/plain", ct)
	}
	body, _ := io.ReadAll(r.Body)
	out := string(body)

	for _, want := range []string{
		`tessera_build_info{build="2026.01.01.12.00",version="0.9.0"} 1`,
		"tessera_devices_total 1",
		`tessera_devices{state="new"} 1`,
		"tessera_devices_online 1",
		`tessera_subnet_addresses_total{cidr="10.0.0.0/24"} 254`,
		`tessera_security_findings{severity="high"} 1`,
		`tessera_collector_up{collector="unifi"} 1`,
		"# TYPE tessera_devices_total gauge",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("metrics output missing %q\n---\n%s", want, out)
		}
	}

	// Auth required (no token → not 200).
	unauth, err := http.Get(ts.URL + "/api/metrics")
	if err != nil {
		t.Fatal(err)
	}
	unauth.Body.Close()
	if unauth.StatusCode == 200 {
		t.Errorf("metrics should require auth, got 200")
	}
}
