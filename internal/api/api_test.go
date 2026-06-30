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

func TestForgetHost(t *testing.T) {
	ts := setup(t)
	// Host exists.
	if detail := getJSON[HostDetail](t, ts.URL+"/api/host?id=mac:b8:27:eb:11:22:33"); detail.Host.StableID == "" {
		t.Fatal("seeded host missing before forget")
	}
	// Forget it.
	r := authPost(t, ts.URL+"/api/host/forget", map[string]any{"stable_id": "mac:b8:27:eb:11:22:33"})
	if r.StatusCode != 200 {
		t.Fatalf("forget → %d", r.StatusCode)
	}
	var resp struct {
		OK                  bool  `json:"ok"`
		ObservationsRemoved int64 `json:"observations_removed"`
	}
	_ = json.NewDecoder(r.Body).Decode(&resp)
	r.Body.Close()
	if !resp.OK || resp.ObservationsRemoved == 0 {
		t.Fatalf("forget response = %+v, want ok + >0 removed", resp)
	}
	// Host is gone after reconcile.
	gone := authGet(t, ts.URL+"/api/host?id=mac:b8:27:eb:11:22:33")
	gone.Body.Close()
	if gone.StatusCode != 404 {
		t.Fatalf("after forget, GET host → %d, want 404", gone.StatusCode)
	}
	// Unknown host → 404.
	r2 := authPost(t, ts.URL+"/api/host/forget", map[string]any{"stable_id": "mac:00:00:00:00:00:00"})
	r2.Body.Close()
	if r2.StatusCode != 404 {
		t.Fatalf("forget unknown → %d, want 404", r2.StatusCode)
	}
}

func TestDeleteArtifact(t *testing.T) {
	ts := setup(t)
	// Seed a service on the host's IP via a rescan-style observation isn't available
	// here, so use the address artifact: the seeded host has IP 10.0.0.20.
	before := getJSON[HostDetail](t, ts.URL+"/api/host?id=mac:b8:27:eb:11:22:33")
	if len(before.Addresses) == 0 {
		t.Fatal("expected a seeded address")
	}
	// Delete the address artifact → its bindings go, host loses the IP.
	r := authPost(t, ts.URL+"/api/host/delete-artifact", map[string]any{
		"stable_id": "mac:b8:27:eb:11:22:33", "kind": "address", "ip": "10.0.0.20",
	})
	var resp struct {
		OK      bool  `json:"ok"`
		Removed int64 `json:"observations_removed"`
	}
	if r.StatusCode != 200 {
		t.Fatalf("delete-artifact → %d", r.StatusCode)
	}
	_ = json.NewDecoder(r.Body).Decode(&resp)
	r.Body.Close()
	if !resp.OK || resp.Removed == 0 {
		t.Fatalf("delete-artifact resp = %+v, want ok + >0 removed", resp)
	}
	after := getJSON[HostDetail](t, ts.URL+"/api/host?id=mac:b8:27:eb:11:22:33")
	for _, a := range after.Addresses {
		if a.IP == "10.0.0.20" {
			t.Errorf("address 10.0.0.20 should be gone after delete")
		}
	}
	// Unknown kind → 400.
	bad := authPost(t, ts.URL+"/api/host/delete-artifact", map[string]any{"stable_id": "mac:b8:27:eb:11:22:33", "kind": "nope"})
	bad.Body.Close()
	if bad.StatusCode != 400 {
		t.Errorf("unknown kind → %d, want 400", bad.StatusCode)
	}
}

func TestMergeHosts(t *testing.T) {
	ts := setup(t)
	// setup() seeds one host (mac:b8:27:eb:11:22:33). Self-merge is rejected.
	bad := authPost(t, ts.URL+"/api/host/merge", map[string]any{"primary": "mac:b8:27:eb:11:22:33", "secondary": "mac:b8:27:eb:11:22:33"})
	bad.Body.Close()
	if bad.StatusCode != 400 {
		t.Fatalf("self-merge → %d, want 400", bad.StatusCode)
	}
	// Merge a (currently-nonexistent) identity into the host; it's recorded and
	// surfaced as merged_from on the primary.
	r := authPost(t, ts.URL+"/api/host/merge", map[string]any{"primary": "mac:b8:27:eb:11:22:33", "secondary": "ip:10.9.9.9"})
	if r.StatusCode != 200 {
		t.Fatalf("merge → %d", r.StatusCode)
	}
	r.Body.Close()
	detail := getJSON[HostDetail](t, ts.URL+"/api/host?id=mac:b8:27:eb:11:22:33")
	found := false
	for _, s := range detail.MergedFrom {
		if s == "ip:10.9.9.9" {
			found = true
		}
	}
	if !found {
		t.Fatalf("merged_from = %v, want it to contain ip:10.9.9.9", detail.MergedFrom)
	}
	// Split it back out.
	u := authPost(t, ts.URL+"/api/host/unmerge", map[string]any{"secondary": "ip:10.9.9.9"})
	u.Body.Close()
	if u.StatusCode != 200 {
		t.Fatalf("unmerge → %d", u.StatusCode)
	}
	d2 := getJSON[HostDetail](t, ts.URL+"/api/host?id=mac:b8:27:eb:11:22:33")
	if len(d2.MergedFrom) != 0 {
		t.Errorf("after split, merged_from = %v, want empty", d2.MergedFrom)
	}
}

func TestTagsRoundTrip(t *testing.T) {
	ts := setup(t)
	// Multiple tags; whitespace + an embedded comma should be normalized away.
	r := authPost(t, ts.URL+"/api/host/annotate", map[string]any{
		"stable_id": "mac:b8:27:eb:11:22:33", "tags": []string{" iot ", "cameras", "a,b", ""},
	})
	if r.StatusCode != 200 {
		t.Fatalf("annotate tags → %d", r.StatusCode)
	}
	r.Body.Close()
	detail := getJSON[HostDetail](t, ts.URL+"/api/host?id=mac:b8:27:eb:11:22:33")
	got := detail.Host.Tags
	want := []string{"iot", "cameras", "a b"}
	if len(got) != len(want) {
		t.Fatalf("tags = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("tag[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestModelAnnotation(t *testing.T) {
	ts := setup(t)
	r := authPost(t, ts.URL+"/api/host/annotate", map[string]any{
		"stable_id": "mac:b8:27:eb:11:22:33", "model": "Raspberry Pi 5",
	})
	if r.StatusCode != 200 {
		t.Fatalf("annotate model → %d", r.StatusCode)
	}
	r.Body.Close()
	detail := getJSON[HostDetail](t, ts.URL+"/api/host?id=mac:b8:27:eb:11:22:33")
	if detail.Host.Model != "Raspberry Pi 5" {
		t.Errorf("model annotation not reflected: %q", detail.Host.Model)
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
