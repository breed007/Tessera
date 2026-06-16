package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/tessera/tessera/internal/account"
	"github.com/tessera/tessera/internal/config"
	"github.com/tessera/tessera/internal/secret"
	"github.com/tessera/tessera/internal/settings"
	"github.com/tessera/tessera/internal/store/sqlite"
)

// authServer builds a minimal API server with an admin and a viewer account.
func authServer(t *testing.T) *httptest.Server {
	t.Helper()
	ctx := context.Background()
	st, err := sqlite.Open(filepath.Join(t.TempDir(), "auth.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	accounts := account.NewManager(st)
	if err := accounts.CreateUser(ctx, "sys", "admin", "adminpass1", account.RoleAdmin); err != nil {
		t.Fatal(err)
	}
	if err := accounts.CreateUser(ctx, "sys", "viewer", "viewerpass1", account.RoleViewer); err != nil {
		t.Fatal(err)
	}
	cipher, _ := secret.New(secret.GenerateKey())
	srv := New(Options{
		ListenAddr: "127.0.0.1:0", Accounts: accounts, Settings: settings.New(st, cipher),
		EffectiveConfig: config.Default(), Store: st,
		Reconcile: func(context.Context) error { return nil },
	})
	ts := httptest.NewServer(srv.routes())
	t.Cleanup(ts.Close)
	return ts
}

// loginClient logs in and returns a cookie-jar client carrying the session.
func loginClient(t *testing.T, base, user, pass string) *http.Client {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar}
	body, _ := json.Marshal(map[string]string{"username": user, "password": pass})
	r, err := c.Post(base+"/api/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		t.Fatalf("login %s → %d", user, r.StatusCode)
	}
	return c
}

func TestLoginBadCredentials(t *testing.T) {
	ts := authServer(t)
	body, _ := json.Marshal(map[string]string{"username": "admin", "password": "wrong"})
	r, _ := http.Post(ts.URL+"/api/login", "application/json", bytes.NewReader(body))
	if r.StatusCode != 401 {
		t.Errorf("bad login = %d, want 401", r.StatusCode)
	}
}

func TestViewerIsReadOnly(t *testing.T) {
	ts := authServer(t)
	viewer := loginClient(t, ts.URL, "viewer", "viewerpass1")

	// Viewer can read.
	r, _ := viewer.Get(ts.URL + "/api/summary")
	if r.StatusCode != 200 {
		t.Errorf("viewer read = %d, want 200", r.StatusCode)
	}
	// Viewer cannot write (annotate) or manage users/settings.
	for _, path := range []string{"/api/host/annotate", "/api/users", "/api/settings"} {
		method := http.MethodPost
		if path == "/api/settings" {
			method = http.MethodPut
		}
		req, _ := http.NewRequest(method, ts.URL+path, bytes.NewReader([]byte("{}")))
		req.Header.Set("Content-Type", "application/json")
		resp, _ := viewer.Do(req)
		if resp.StatusCode != 403 {
			t.Errorf("viewer %s %s = %d, want 403", method, path, resp.StatusCode)
		}
	}
}

func TestAdminCanManage(t *testing.T) {
	ts := authServer(t)
	admin := loginClient(t, ts.URL, "admin", "adminpass1")

	// Admin can list users and create one.
	r, _ := admin.Get(ts.URL + "/api/users")
	if r.StatusCode != 200 {
		t.Fatalf("admin list users = %d", r.StatusCode)
	}
	body, _ := json.Marshal(map[string]string{"username": "bob", "password": "bobpass12", "role": "viewer"})
	cr, _ := admin.Post(ts.URL+"/api/users", "application/json", bytes.NewReader(body))
	if cr.StatusCode != 200 {
		t.Errorf("admin create user = %d", cr.StatusCode)
	}
	// The new viewer can now log in.
	loginClient(t, ts.URL, "bob", "bobpass12")
}

func TestLogout(t *testing.T) {
	ts := authServer(t)
	c := loginClient(t, ts.URL, "admin", "adminpass1")
	if r, _ := c.Post(ts.URL+"/api/logout", "application/json", nil); r.StatusCode != 200 {
		t.Fatalf("logout = %d", r.StatusCode)
	}
	// After logout the session cookie is cleared → 401.
	if r, _ := c.Get(ts.URL + "/api/summary"); r.StatusCode != 401 {
		t.Errorf("post-logout read = %d, want 401", r.StatusCode)
	}
}

func TestIsLoopbackAddr(t *testing.T) {
	for _, a := range []string{"127.0.0.1:10404", "localhost:80", "[::1]:10404"} {
		if !isLoopbackAddr(a) {
			t.Errorf("%s should be loopback", a)
		}
	}
	for _, a := range []string{"0.0.0.0:10404", ":10404", "192.168.1.5:10404"} {
		if isLoopbackAddr(a) {
			t.Errorf("%s should NOT be loopback", a)
		}
	}
}

func TestCheckBindSecurity(t *testing.T) {
	if err := CheckBindSecurity("127.0.0.1:10404", false, false); err != nil {
		t.Errorf("loopback no auth: %v", err)
	}
	if err := CheckBindSecurity("0.0.0.0:10404", false, false); err == nil {
		t.Error("non-loopback without auth should be refused")
	}
	if err := CheckBindSecurity("0.0.0.0:10404", true, false); err != nil {
		t.Errorf("non-loopback with auth: %v", err)
	}
	if err := CheckBindSecurity("0.0.0.0:10404", false, true); err != nil {
		t.Errorf("allow_insecure: %v", err)
	}
}
