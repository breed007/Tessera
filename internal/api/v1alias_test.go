package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/tessera/tessera/internal/account"
	"github.com/tessera/tessera/internal/config"
	"github.com/tessera/tessera/internal/secret"
	"github.com/tessera/tessera/internal/settings"
	"github.com/tessera/tessera/internal/store/sqlite"
)

// TestV1Alias confirms /api/v1/* resolves to the same handlers as /api/* (auth
// and all), so consumers can pin the stable prefix.
func TestV1Alias(t *testing.T) {
	ctx := context.Background()
	st, err := sqlite.Open(filepath.Join(t.TempDir(), "v1.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	cipher, _ := secret.New(secret.GenerateKey())
	srv := New(Options{
		ListenAddr: "127.0.0.1:0", Token: testToken, Accounts: account.NewManager(st),
		Settings: settings.New(st, cipher), EffectiveConfig: config.Default(), Store: st,
	})
	ts := httptest.NewServer(srv.routes())
	t.Cleanup(ts.Close)

	get := func(path string, auth bool) int {
		req, _ := http.NewRequest(http.MethodGet, ts.URL+path, nil)
		if auth {
			req.Header.Set("Authorization", "Bearer "+testToken)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	// Authed reads work under both prefixes.
	for _, p := range []string{"/api/summary", "/api/v1/summary", "/api/hosts", "/api/v1/hosts", "/api/events", "/api/v1/events"} {
		if code := get(p, true); code != 200 {
			t.Errorf("GET %s (authed) → %d, want 200", p, code)
		}
	}
	// Auth still applies through the alias (no free pass via /v1).
	if code := get("/api/v1/summary", false); code != 401 {
		t.Errorf("GET /api/v1/summary (no auth) → %d, want 401", code)
	}
	// The OpenAPI spec is public under both prefixes.
	if code := get("/api/openapi.json", false); code != 200 {
		t.Errorf("GET /api/openapi.json → %d, want 200", code)
	}
	if code := get("/api/v1/openapi.json", false); code != 200 {
		t.Errorf("GET /api/v1/openapi.json → %d, want 200", code)
	}
}
