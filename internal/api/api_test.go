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

	"github.com/breed007/Tessera/internal/account"
	"github.com/breed007/Tessera/internal/config"
	"github.com/breed007/Tessera/internal/entity"
	"github.com/breed007/Tessera/internal/observation"
	"github.com/breed007/Tessera/internal/reconcile"
	"github.com/breed007/Tessera/internal/secret"
	"github.com/breed007/Tessera/internal/settings"
	"github.com/breed007/Tessera/internal/store/sqlite"
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

func TestBulkActions(t *testing.T) {
	ts := setup(t)
	const id = "mac:b8:27:eb:11:22:33"
	// Bulk mark expected.
	r := authPost(t, ts.URL+"/api/hosts/bulk", map[string]any{"stable_ids": []string{id}, "action": "expected"})
	if r.StatusCode != 200 {
		t.Fatalf("bulk expected → %d", r.StatusCode)
	}
	var resp struct {
		Affected int `json:"affected"`
	}
	_ = json.NewDecoder(r.Body).Decode(&resp)
	r.Body.Close()
	if resp.Affected != 1 {
		t.Fatalf("affected = %d, want 1", resp.Affected)
	}
	d := getJSON[HostDetail](t, ts.URL+"/api/host?id="+id)
	if !d.Host.IsExpected {
		t.Errorf("host should be expected after bulk")
	}
	// Bulk add tags (merges with existing).
	r2 := authPost(t, ts.URL+"/api/hosts/bulk", map[string]any{"stable_ids": []string{id}, "action": "add_tags", "tags": []string{"iot", "lab"}})
	r2.Body.Close()
	d2 := getJSON[HostDetail](t, ts.URL+"/api/host?id="+id)
	if len(d2.Host.Tags) != 2 {
		t.Errorf("tags = %v, want [iot lab]", d2.Host.Tags)
	}
	// Unknown action → 400; empty selection → 400.
	for _, bad := range []map[string]any{
		{"stable_ids": []string{id}, "action": "nope"},
		{"stable_ids": []string{}, "action": "expected"},
	} {
		rb := authPost(t, ts.URL+"/api/hosts/bulk", bad)
		rb.Body.Close()
		if rb.StatusCode != 400 {
			t.Errorf("bad bulk %v → %d, want 400", bad, rb.StatusCode)
		}
	}
	// Bulk forget removes the device.
	rf := authPost(t, ts.URL+"/api/hosts/bulk", map[string]any{"stable_ids": []string{id}, "action": "forget"})
	rf.Body.Close()
	gone := authGet(t, ts.URL+"/api/host?id="+id)
	gone.Body.Close()
	if gone.StatusCode != 404 {
		t.Errorf("after bulk forget, host → %d, want 404", gone.StatusCode)
	}
}

func TestCreateHost(t *testing.T) {
	ts := setup(t)
	// Bad MAC → 400.
	bad := authPost(t, ts.URL+"/api/host/create", map[string]any{"mac": "nope"})
	bad.Body.Close()
	if bad.StatusCode != 400 {
		t.Fatalf("bad mac → %d, want 400", bad.StatusCode)
	}
	r := authPost(t, ts.URL+"/api/host/create", map[string]any{
		"mac": "de:ad:be:ef:00:01", "ip": "10.0.0.250", "display_name": "Planned NAS", "device_class": "NAS",
	})
	if r.StatusCode != 200 {
		t.Fatalf("create host → %d", r.StatusCode)
	}
	var resp struct {
		StableID string `json:"stable_id"`
	}
	_ = json.NewDecoder(r.Body).Decode(&resp)
	r.Body.Close()
	if resp.StableID != "mac:de:ad:be:ef:00:01" {
		t.Fatalf("stable_id = %q", resp.StableID)
	}
	detail := getJSON[HostDetail](t, ts.URL+"/api/host?id="+resp.StableID)
	if detail.Host.DisplayName != "Planned NAS" || !detail.Host.IsExpected {
		t.Errorf("created host wrong: %+v", detail.Host)
	}
	hasIP := false
	for _, a := range detail.Addresses {
		if a.IP == "10.0.0.250" {
			hasIP = true
		}
	}
	if !hasIP {
		t.Errorf("created host should own 10.0.0.250: %+v", detail.Addresses)
	}
}

func TestCreateHostDoesNotStealIP(t *testing.T) {
	ts := setup(t)
	// setup() seeds mac:b8:27:eb:11:22:33 owning 10.0.0.20 (discovery, conf 95).
	// Documenting a different device on the SAME IP must not yank it.
	r := authPost(t, ts.URL+"/api/host/create", map[string]any{
		"mac": "de:ad:be:ef:00:09", "ip": "10.0.0.20", "display_name": "Ghost",
	})
	if r.StatusCode != 200 {
		t.Fatalf("create → %d", r.StatusCode)
	}
	var resp struct {
		Warning string `json:"warning"`
	}
	_ = json.NewDecoder(r.Body).Decode(&resp)
	r.Body.Close()
	if resp.Warning == "" {
		t.Errorf("expected a warning that the IP is already assigned")
	}
	// The real device keeps 10.0.0.20.
	real := getJSON[HostDetail](t, ts.URL+"/api/host?id=mac:b8:27:eb:11:22:33")
	got := false
	for _, a := range real.Addresses {
		if a.IP == "10.0.0.20" {
			got = true
		}
	}
	if !got {
		t.Errorf("real host lost 10.0.0.20 to the manual ghost — IP was stolen")
	}
}

func TestBulkCap(t *testing.T) {
	ts := setup(t)
	ids := make([]string, 2001)
	for i := range ids {
		ids[i] = "mac:00:00:00:00:00:01"
	}
	r := authPost(t, ts.URL+"/api/hosts/bulk", map[string]any{"stable_ids": ids, "action": "expected"})
	r.Body.Close()
	if r.StatusCode != 400 {
		t.Errorf("bulk of 2001 → %d, want 400", r.StatusCode)
	}
}

func TestCreateSubnet(t *testing.T) {
	ts := setup(t)
	bad := authPost(t, ts.URL+"/api/subnet/create", map[string]any{"cidr": "not-a-cidr"})
	bad.Body.Close()
	if bad.StatusCode != 400 {
		t.Fatalf("bad cidr → %d, want 400", bad.StatusCode)
	}
	r := authPost(t, ts.URL+"/api/subnet/create", map[string]any{"cidr": "192.168.50.0/24", "name": "IoT"})
	r.Body.Close()
	if r.StatusCode != 200 {
		t.Fatalf("create subnet → %d", r.StatusCode)
	}
	subnets := getJSON[[]entity.Subnet](t, ts.URL+"/api/subnets")
	found := false
	for _, s := range subnets {
		if s.CIDR == "192.168.50.0/24" && s.Name == "IoT" {
			found = true
		}
	}
	if !found {
		t.Errorf("created subnet not found: %+v", subnets)
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
