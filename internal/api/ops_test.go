package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/tessera/tessera/internal/account"
	"github.com/tessera/tessera/internal/config"
	"github.com/tessera/tessera/internal/secret"
	"github.com/tessera/tessera/internal/settings"
	"github.com/tessera/tessera/internal/store/sqlite"
)

func TestOps(t *testing.T) {
	ctx := context.Background()
	dsn := filepath.Join(t.TempDir(), "ops.db")
	st, err := sqlite.Open(dsn)
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
		Settings: settings.New(st, cipher), EffectiveConfig: config.Default(), Store: st, DSN: dsn,
	})
	ts := httptest.NewServer(srv.routes())
	t.Cleanup(ts.Close)

	// Audit: creating a user records an entry.
	cu := authPost(t, ts.URL+"/api/users", map[string]any{"username": "bob", "password": "bobpass12", "role": "viewer"})
	cu.Body.Close()
	var audit struct {
		Entries []map[string]any `json:"entries"`
	}
	ar := authGet(t, ts.URL+"/api/audit")
	defer ar.Body.Close()
	if err := json.NewDecoder(ar.Body).Decode(&audit); err != nil {
		t.Fatal(err)
	}
	if len(audit.Entries) == 0 {
		t.Errorf("audit should have at least the user.create entry")
	}

	// Backup: streams a real SQLite file.
	br := authGet(t, ts.URL+"/api/backup")
	defer br.Body.Close()
	if br.StatusCode != 200 {
		t.Fatalf("backup → %d", br.StatusCode)
	}
	body, _ := io.ReadAll(br.Body)
	if len(body) < len(sqliteMagic) || string(body[:len(sqliteMagic)]) != sqliteMagic {
		t.Errorf("backup is not a SQLite file (header %q)", body[:min(16, len(body))])
	}

	// Restore: garbage is rejected.
	bad := authPostRaw(t, ts.URL+"/api/restore", []byte("not a database"))
	bad.Body.Close()
	if bad.StatusCode != 400 {
		t.Errorf("garbage restore → %d, want 400", bad.StatusCode)
	}
	// A SQLite-headed upload is staged (onRestart is nil here, so no restart).
	good := authPostRaw(t, ts.URL+"/api/restore", body)
	good.Body.Close()
	if good.StatusCode != 200 {
		t.Fatalf("valid restore → %d, want 200", good.StatusCode)
	}
	if _, err := os.Stat(dsn + ".restore"); err != nil {
		t.Errorf("restore should have staged %s.restore", dsn)
	}
}

func authPostRaw(t *testing.T, url string, body []byte) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+testToken)
	r, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return r
}
