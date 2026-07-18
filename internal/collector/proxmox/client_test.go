package proxmox

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestTicketAuth exercises the username/password flow: a login POST mints a
// ticket, and subsequent GETs must present it as the PVEAuthCookie.
func TestTicketAuth(t *testing.T) {
	logins := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api2/json/access/ticket":
			logins++
			_ = r.ParseForm()
			if r.Form.Get("username") != "monitor@pve" || r.Form.Get("password") != "s3cret" {
				w.WriteHeader(401)
				return
			}
			w.Write([]byte(`{"data":{"ticket":"PVE:monitor@pve:ABC123","CSRFPreventionToken":"x"}}`))
		case "/api2/json/nodes":
			if c, err := r.Cookie("PVEAuthCookie"); err != nil || c.Value != "PVE:monitor@pve:ABC123" {
				w.WriteHeader(401)
				return
			}
			w.Write([]byte(`{"data":[{"node":"pve1"},{"node":"pve2"}]}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	c := New(Config{BaseURL: srv.URL, Auth: Auth{Username: "monitor@pve", Password: "s3cret"}})
	nodes, err := c.fetchNodes(context.Background())
	if err != nil {
		t.Fatalf("fetchNodes: %v", err)
	}
	if len(nodes) != 2 {
		t.Fatalf("got %d nodes, want 2", len(nodes))
	}
	// A second call should reuse the cached ticket (no re-login).
	if _, err := c.fetchNodes(context.Background()); err != nil {
		t.Fatalf("second fetchNodes: %v", err)
	}
	if logins != 1 {
		t.Errorf("logged in %d times, want 1 (ticket should be cached)", logins)
	}
}

// TestTokenAuth confirms token mode sends the Authorization header and never
// hits the ticket endpoint.
func TestTokenAuth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api2/json/access/ticket" {
			t.Error("token mode must not call /access/ticket")
		}
		if !strings.HasPrefix(r.Header.Get("Authorization"), "PVEAPIToken=root@pam!t=abc") {
			w.WriteHeader(401)
			return
		}
		w.Write([]byte(`{"data":[{"node":"pve1"}]}`))
	}))
	defer srv.Close()

	c := New(Config{BaseURL: srv.URL, Auth: Auth{Token: "root@pam!t=abc"}})
	nodes, err := c.fetchNodes(context.Background())
	if err != nil || len(nodes) != 1 {
		t.Fatalf("nodes=%v err=%v", nodes, err)
	}
}

func TestAuthMode(t *testing.T) {
	if !(Auth{Token: "x"}).usesToken() {
		t.Error("token should win")
	}
	if (Auth{Token: "x", Username: "u"}).usesTicket() {
		t.Error("ticket must not be used when a token is present")
	}
	if !(Auth{Username: "u"}).usesTicket() {
		t.Error("username-only should use ticket")
	}
}
