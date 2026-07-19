package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tessera/tessera/internal/account"
	"github.com/tessera/tessera/internal/config"
	"github.com/tessera/tessera/internal/secret"
	"github.com/tessera/tessera/internal/settings"
	"github.com/tessera/tessera/internal/store/sqlite"
)

// TestCustomIconXSSDefenses pins the two controls added after QA found that an
// operator could plant a script-bearing SVG served as active content: uploads
// with scripts are rejected, and served custom icons carry a sandbox CSP +
// nosniff so anything that slips through still can't execute.
func TestCustomIconXSSDefenses(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	st, err := sqlite.Open(filepath.Join(dir, "ico.db"))
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
		DataDir: dir,
	})
	ts := httptest.NewServer(srv.routes())
	t.Cleanup(ts.Close)

	// Upload-side reject of obvious active content.
	for _, bad := range []string{
		`<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`,
		`<svg xmlns="http://www.w3.org/2000/svg"><rect onload="alert(1)"/></svg>`,
		`<svg xmlns="http://www.w3.org/2000/svg"><a href="javascript:alert(1)"><rect/></a></svg>`,
		`<svg xmlns="http://www.w3.org/2000/svg"><foreignObject><body>x</body></foreignObject></svg>`,
	} {
		r := authPost(t, ts.URL+"/api/icons", map[string]any{"id": "bad", "svg": bad})
		if r.StatusCode != http.StatusBadRequest {
			t.Errorf("malicious SVG upload → %d, want 400: %.40s", r.StatusCode, bad)
		}
		r.Body.Close()
	}

	// A clean icon uploads fine…
	clean := `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><rect width="24" height="24"/></svg>`
	if r := authPost(t, ts.URL+"/api/icons", map[string]any{"id": "good", "svg": clean}); r.StatusCode != 200 {
		t.Fatalf("clean SVG upload → %d, want 200", r.StatusCode)
	} else {
		r.Body.Close()
	}

	// …and is served with the sandbox CSP + nosniff (public route, no auth).
	resp, err := http.Get(ts.URL + "/icons/custom/good.svg")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("serve custom icon → %d, want 200", resp.StatusCode)
	}
	csp := resp.Header.Get("Content-Security-Policy")
	if !strings.Contains(csp, "sandbox") || !strings.Contains(csp, "default-src 'none'") {
		t.Errorf("custom icon CSP = %q, want sandbox + default-src 'none'", csp)
	}
	if resp.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("custom icon missing X-Content-Type-Options: nosniff")
	}
}
