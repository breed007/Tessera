package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/breed007/Tessera/internal/account"
	"github.com/breed007/Tessera/internal/config"
	"github.com/breed007/Tessera/internal/secret"
	"github.com/breed007/Tessera/internal/settings"
	"github.com/breed007/Tessera/internal/store/sqlite"
)

// TestGlobalSecurityHeaders pins the app-wide CSP and hardening headers. The
// important property is that script-src is 'self' with NO 'unsafe-inline' /
// 'unsafe-eval' — that's what actually stops injected script from running, and
// it's only achievable because the UI has no inline <script>, no inline event
// handlers, and no eval.
func TestGlobalSecurityHeaders(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	st, err := sqlite.Open(filepath.Join(dir, "csp.db"))
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

	// The UI document and an API response both carry the global policy.
	for _, path := range []string{"/", "/api/version"} {
		resp, err := http.Get(ts.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		csp := resp.Header.Get("Content-Security-Policy")
		if csp == "" {
			t.Fatalf("%s: no Content-Security-Policy", path)
		}
		if !strings.Contains(csp, "script-src 'self'") {
			t.Errorf("%s: CSP lacks script-src 'self': %q", path, csp)
		}
		// The whole point: scripts must not be allowed inline or via eval.
		if strings.Contains(csp, "script-src 'self' 'unsafe-inline'") || strings.Contains(csp, "unsafe-eval") {
			t.Errorf("%s: CSP weakens script-src: %q", path, csp)
		}
		for _, want := range []string{"default-src 'none'", "object-src 'none'", "base-uri 'none'", "frame-ancestors 'none'"} {
			if !strings.Contains(csp, want) {
				t.Errorf("%s: CSP missing %q: %q", path, want, csp)
			}
		}
		if got := resp.Header.Get("X-Content-Type-Options"); got != "nosniff" {
			t.Errorf("%s: X-Content-Type-Options = %q, want nosniff", path, got)
		}
		if got := resp.Header.Get("X-Frame-Options"); got != "DENY" {
			t.Errorf("%s: X-Frame-Options = %q, want DENY", path, got)
		}
		if got := resp.Header.Get("Referrer-Policy"); got != "no-referrer" {
			t.Errorf("%s: Referrer-Policy = %q, want no-referrer", path, got)
		}
	}

	// A route may tighten the policy: operator-uploaded icons keep their sandbox
	// CSP rather than inheriting the (script-permitting) global one.
	if r := authPost(t, ts.URL+"/api/icons", map[string]any{
		"id": "ovr", "svg": `<svg xmlns="http://www.w3.org/2000/svg"><rect width="4" height="4"/></svg>`,
	}); r.StatusCode != 200 {
		t.Fatalf("icon upload → %d", r.StatusCode)
	} else {
		r.Body.Close()
	}
	resp, err := http.Get(ts.URL + "/icons/custom/ovr.svg")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	csp := resp.Header.Get("Content-Security-Policy")
	if !strings.Contains(csp, "sandbox") {
		t.Errorf("custom icon lost its sandbox CSP to the global one: %q", csp)
	}
	if strings.Contains(csp, "script-src 'self'") {
		t.Errorf("custom icon inherited the script-permitting global CSP: %q", csp)
	}
}
