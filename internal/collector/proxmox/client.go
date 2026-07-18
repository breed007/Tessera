// Package proxmox is a read-only Proxmox VE collector. It polls the PVE API for
// VMs (QEMU) and containers (LXC) and maps each guest's virtual NIC(s) to
// observations — MAC↔hostname, device class (VM/CT), OS, and any static IP — so
// guests that show up on the wire as bare "Proxmox Server Solutions" MACs get
// named and classified from the hypervisor's own inventory.
package proxmox

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Auth is one of two Proxmox authentication methods. Prefer an API token (no
// expiry, easy to scope read-only); a username/password falls back to the
// ticket flow. If Token is set it wins.
type Auth struct {
	Token    string // PVEAPIToken value: "user@realm!tokenid=secret"
	Username string // ticket auth: "user@realm" (e.g. root@pam, monitor@pve)
	Password string // ticket auth password
}

// usesToken / usesTicket report which method is configured (token wins).
func (a Auth) usesToken() bool  { return strings.TrimSpace(a.Token) != "" }
func (a Auth) usesTicket() bool { return !a.usesToken() && a.Username != "" }

// Config is the connection to a Proxmox VE node/cluster.
type Config struct {
	BaseURL   string // e.g. https://proxmox.lan:8006
	VerifyTLS bool   // PVE ships a self-signed cert; usually false
	Auth      Auth
}

// Client performs authenticated GETs against the PVE API. Read-only.
type Client struct {
	cfg  Config
	http *http.Client

	mu           sync.Mutex // guards the cached ticket
	ticket       string     // PVEAuthCookie value (ticket auth only)
	ticketExpiry time.Time
}

// New builds a Client. TLS verification is off by default (self-signed PVE cert).
func New(cfg Config) *Client {
	cfg.BaseURL = normalizeBaseURL(cfg.BaseURL)
	return &Client{
		cfg: cfg,
		http: &http.Client{
			Timeout:   30 * time.Second,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: !cfg.VerifyTLS}}, //nolint:gosec // self-signed PVE cert
		},
	}
}

// normalizeBaseURL adds https:// and the default :8006 when missing, trims a
// trailing slash.
func normalizeBaseURL(raw string) string {
	raw = strings.TrimRight(strings.TrimSpace(raw), "/")
	if raw == "" {
		return raw
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	// Add the default API port if the host has none.
	if noScheme := strings.SplitN(raw, "://", 2)[1]; !strings.Contains(noScheme, ":") {
		raw += ":8006"
	}
	return raw
}

// get fetches path under /api2/json and unmarshals the {"data": …} envelope into
// out. In ticket mode a 401 triggers one re-auth + retry (the ticket expired).
func (c *Client) get(ctx context.Context, path string, out any) error {
	err := c.getOnce(ctx, path, out)
	if err != nil && c.cfg.Auth.usesTicket() && strings.Contains(err.Error(), "401") {
		c.invalidateTicket()
		err = c.getOnce(ctx, path, out)
	}
	return err
}

func (c *Client) getOnce(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.cfg.BaseURL+"/api2/json"+path, nil)
	if err != nil {
		return err
	}
	if err := c.authenticate(ctx, req); err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("proxmox: 401 — check the credentials and that the user has PVEAuditor on /")
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("proxmox: %s → %s", path, resp.Status)
	}
	var env struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return fmt.Errorf("proxmox: decode %s: %w", path, err)
	}
	return json.Unmarshal(env.Data, out)
}

// authenticate attaches the right credential to req: an API-token header, or a
// PVEAuthCookie ticket (acquired/cached on demand).
func (c *Client) authenticate(ctx context.Context, req *http.Request) error {
	if c.cfg.Auth.usesToken() {
		req.Header.Set("Authorization", "PVEAPIToken="+c.cfg.Auth.Token)
		return nil
	}
	ticket, err := c.ensureTicket(ctx)
	if err != nil {
		return err
	}
	req.AddCookie(&http.Cookie{Name: "PVEAuthCookie", Value: ticket})
	return nil
}

// ensureTicket returns a valid PVE ticket, acquiring a fresh one when the cache
// is empty or near expiry. PVE tickets last ~2h; we refresh with a margin.
func (c *Client) ensureTicket(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ticket != "" && time.Now().Before(c.ticketExpiry) {
		return c.ticket, nil
	}
	ticket, err := c.acquireTicket(ctx)
	if err != nil {
		return "", err
	}
	c.ticket = ticket
	c.ticketExpiry = time.Now().Add(90 * time.Minute) // refresh well before the ~2h expiry
	return ticket, nil
}

func (c *Client) invalidateTicket() {
	c.mu.Lock()
	c.ticket = ""
	c.mu.Unlock()
}

// acquireTicket performs the PVE ticket login (POST /access/ticket). Read-only
// GETs need only the ticket cookie — the CSRF token is required for writes only,
// which this collector never does.
func (c *Client) acquireTicket(ctx context.Context) (string, error) {
	form := url.Values{"username": {c.cfg.Auth.Username}, "password": {c.cfg.Auth.Password}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.BaseURL+"/api2/json/access/ticket",
		strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode == http.StatusUnauthorized {
		return "", fmt.Errorf("proxmox: 401 — check the username (user@realm) and password")
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("proxmox: login → %s", resp.Status)
	}
	var env struct {
		Data struct {
			Ticket string `json:"ticket"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return "", fmt.Errorf("proxmox: decode ticket: %w", err)
	}
	if env.Data.Ticket == "" {
		return "", fmt.Errorf("proxmox: login returned no ticket")
	}
	return env.Data.Ticket, nil
}
