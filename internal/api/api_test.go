package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
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

const testToken = "test-admin-token"

// setup builds a fully wired API server (sqlite + accounts + settings) with an
// admin bearer token, seeds a discovered Pi, and returns the test server.
func setup(t *testing.T) *httptest.Server {
	t.Helper()
	ctx := context.Background()
	st, err := sqlite.Open(filepath.Join(t.TempDir(), "api.db"))
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
	rec(observation.SourcePassiveARP, observation.SubjectMAC, "b8:27:eb:11:22:33", observation.AttrIPBinding, "10.0.0.20", 95)
	rec(observation.SourcePassiveDHCP, observation.SubjectMAC, "b8:27:eb:11:22:33", observation.AttrHostname, "pi-dhcp", 80)

	clock := t0.Add(time.Minute)
	recon := reconcile.New(st, nil, reconcile.Params{Now: func() time.Time { return clock }})
	if _, err := recon.Rebuild(ctx); err != nil {
		t.Fatal(err)
	}

	accounts := account.NewManager(st)
	if err := accounts.CreateUser(ctx, "test", "viewer1", "viewerpass1", account.RoleViewer); err != nil {
		t.Fatal(err)
	}
	cipher, _ := secret.New(secret.GenerateKey())
	srv := New(Options{
		ListenAddr:      "127.0.0.1:0",
		Token:           testToken,
		Accounts:        accounts,
		Settings:        settings.New(st, cipher),
		EffectiveConfig: config.Default(),
		Store:           st,
		Reconcile:       func(ctx context.Context) error { _, e := recon.Rebuild(ctx); return e },
	})
	ts := httptest.NewServer(srv.routes())
	t.Cleanup(ts.Close)
	return ts
}

func authGet(t *testing.T, url string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	r, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func getJSON[T any](t *testing.T, url string) T {
	t.Helper()
	r := authGet(t, url)
	defer r.Body.Close()
	if r.StatusCode != 200 {
		t.Fatalf("GET %s → %d", url, r.StatusCode)
	}
	var v T
	if err := json.NewDecoder(r.Body).Decode(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

func authPost(t *testing.T, url string, body any) *http.Response {
	t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(b))
	req.Header.Set("Authorization", "Bearer "+testToken)
	req.Header.Set("Content-Type", "application/json")
	r, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestReadAPI(t *testing.T) {
	ts := setup(t)
	sum := getJSON[Summary](t, ts.URL+"/api/summary")
	if sum.Hosts != 1 || sum.Addresses != 1 || sum.NewDevices != 1 {
		t.Errorf("summary = %+v", sum)
	}
	hosts := getJSON[[]HostRow](t, ts.URL+"/api/hosts")
	if len(hosts) != 1 || hosts[0].Vendor != "Raspberry Pi Foundation" {
		t.Fatalf("hosts = %+v", hosts)
	}
	detail := getJSON[HostDetail](t, ts.URL+"/api/host?id=mac:b8:27:eb:11:22:33")
	if len(detail.Observations) < 2 || len(detail.Addresses) != 1 {
		t.Errorf("detail wrong: %+v", detail)
	}
}

func TestUnauthenticated(t *testing.T) {
	ts := setup(t)
	// No credentials → 401 on the API; static UI stays public.
	r, _ := http.Get(ts.URL + "/api/summary")
	if r.StatusCode != 401 {
		t.Errorf("unauth API = %d, want 401", r.StatusCode)
	}
	r2, _ := http.Get(ts.URL + "/")
	if r2.StatusCode != 200 {
		t.Errorf("static UI = %d, want 200", r2.StatusCode)
	}
}

func TestAnnotationReflected(t *testing.T) {
	ts := setup(t)
	r := authPost(t, ts.URL+"/api/host/annotate", map[string]any{
		"stable_id": "mac:b8:27:eb:11:22:33", "display_name": "Living Room Pi", "is_expected": true,
	})
	if r.StatusCode != 200 {
		t.Fatalf("annotate → %d", r.StatusCode)
	}
	r.Body.Close()
	detail := getJSON[HostDetail](t, ts.URL+"/api/host?id=mac:b8:27:eb:11:22:33")
	if detail.Host.DisplayName != "Living Room Pi" || !detail.Host.IsExpected {
		t.Errorf("annotation not reflected: %+v", detail.Host)
	}
}

func TestIgnoreStatus(t *testing.T) {
	ts := setup(t)
	r := authPost(t, ts.URL+"/api/host/annotate", map[string]any{
		"stable_id": "mac:b8:27:eb:11:22:33", "ignored": true,
	})
	if r.StatusCode != 200 {
		t.Fatalf("annotate ignored → %d", r.StatusCode)
	}
	r.Body.Close()
	detail := getJSON[HostDetail](t, ts.URL+"/api/host?id=mac:b8:27:eb:11:22:33")
	if !detail.Host.Ignored {
		t.Errorf("ignored not reflected: %+v", detail.Host)
	}
}

func TestVersionEndpoint(t *testing.T) {
	ts := setup(t)
	// Public endpoint (no auth needed).
	v := getJSON[map[string]string](t, ts.URL+"/api/version")
	if _, ok := v["version"]; !ok {
		t.Errorf("version endpoint missing version field: %+v", v)
	}
}
