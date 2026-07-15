package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/tessera/tessera/internal/account"
	"github.com/tessera/tessera/internal/config"
	"github.com/tessera/tessera/internal/secret"
	"github.com/tessera/tessera/internal/settings"
	"github.com/tessera/tessera/internal/store/sqlite"
)

func TestAPITokens(t *testing.T) {
	ctx := context.Background()
	st, err := sqlite.Open(filepath.Join(t.TempDir(), "tok.db"))
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

	// Create a viewer token (via the admin env token).
	r := authPost(t, ts.URL+"/api/tokens", map[string]any{"name": "cablemap", "role": "viewer"})
	if r.StatusCode != 200 {
		t.Fatalf("create token → %d", r.StatusCode)
	}
	var created struct {
		ID    int64  `json:"id"`
		Token string `json:"token"`
	}
	_ = json.NewDecoder(r.Body).Decode(&created)
	r.Body.Close()
	if created.Token == "" || created.ID == 0 {
		t.Fatalf("create token resp = %+v", created)
	}

	// The token authenticates a read request…
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/summary", nil)
	req.Header.Set("Authorization", "Bearer "+created.Token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("read with token → %d, want 200", resp.StatusCode)
	}
	// …but a viewer token cannot write (403).
	wreq, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/host/annotate", nil)
	wreq.Header.Set("Authorization", "Bearer "+created.Token)
	wresp, _ := http.DefaultClient.Do(wreq)
	wresp.Body.Close()
	if wresp.StatusCode != 403 {
		t.Errorf("viewer token write → %d, want 403", wresp.StatusCode)
	}

	// Revoke it → it stops working.
	del, _ := http.NewRequest(http.MethodDelete, ts.URL+"/api/tokens/"+strconv.FormatInt(created.ID, 10), nil)
	del.Header.Set("Authorization", "Bearer "+testToken)
	dr, err := http.DefaultClient.Do(del)
	if err != nil {
		t.Fatal(err)
	}
	dr.Body.Close()
	req2, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/summary", nil)
	req2.Header.Set("Authorization", "Bearer "+created.Token)
	resp2, _ := http.DefaultClient.Do(req2)
	resp2.Body.Close()
	if resp2.StatusCode == 200 {
		t.Errorf("revoked token still works")
	}

	// The OpenAPI spec is public.
	spec, _ := http.Get(ts.URL + "/api/openapi.json")
	spec.Body.Close()
	if spec.StatusCode != 200 {
		t.Errorf("openapi.json → %d, want 200 (public)", spec.StatusCode)
	}
}
