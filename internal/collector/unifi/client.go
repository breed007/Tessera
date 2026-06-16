package unifi

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"time"
)

// Auth selects how the client authenticates (§4.3). Local methods only by
// default; the cloud Site Manager key is an explicit documented fallback, not
// wired here.
type Auth struct {
	// Username/Password: a dedicated local read-only admin account. Works across
	// all controller types. Do NOT use a UI.com cloud SSO account (MFA → 401s).
	Username string
	Password string
	// APIKey: a Network Application API key (UniFi OS Integrations). Sent as the
	// X-API-KEY header; no login round-trip.
	APIKey string
}

func (a Auth) usesAPIKey() bool { return a.APIKey != "" }

// Config is the client's connection configuration (secrets arrive via Auth,
// never logged).
type Config struct {
	BaseURL    string // e.g. https://192.168.10.1  (OS Server: include :11443)
	PathPrefix string // "/proxy/network" (UniFi OS), "" (8443 software controller)
	Site       string // controller site, default "default"
	VerifyTLS  bool   // self-signed controllers: false
	Auth       Auth
}

// Client is a read-only HTTP client for the local UniFi controller. It performs
// GETs only; it never mutates controller state.
type Client struct {
	cfg      Config
	http     *http.Client
	unifiOS  bool // UniFi OS console (proxy path + /api/auth/login) vs legacy software controller
	loggedIn bool
}

// New builds a Client. TLS verification is controlled by cfg.VerifyTLS;
// self-signed controllers are the norm, so verification is typically off and a
// pin can be added later.
func New(cfg Config) (*Client, error) {
	if cfg.Site == "" {
		cfg.Site = "default"
	}
	cfg.BaseURL = normalizeBaseURL(cfg.BaseURL)
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("unifi: cookie jar: %w", err)
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: !cfg.VerifyTLS}, //nolint:gosec // self-signed controllers; pinning is a later milestone
	}
	return &Client{
		cfg:     cfg,
		http:    &http.Client{Timeout: 30 * time.Second, Jar: jar, Transport: tr},
		unifiOS: strings.Contains(cfg.PathPrefix, "proxy"),
	}, nil
}

// normalizeBaseURL makes the controller URL forgiving: a bare host or IP gets an
// https:// scheme (UniFi controllers are HTTPS), and any trailing slash is
// trimmed so BaseURL+path joins cleanly. This avoids the common "unsupported
// protocol scheme" error when an operator types just "192.168.1.1".
func normalizeBaseURL(u string) string {
	u = strings.TrimSpace(u)
	u = strings.TrimRight(u, "/")
	if u != "" && !strings.Contains(u, "://") {
		u = "https://" + u
	}
	return u
}

// login establishes a session for username/password auth. No-op for API-key auth.
// It must never log the credential.
func (c *Client) login(ctx context.Context) error {
	if c.cfg.Auth.usesAPIKey() || c.loggedIn {
		return nil
	}
	path := "/api/login"
	if c.unifiOS {
		path = "/api/auth/login" // UniFi OS consoles authenticate at the root, not under /proxy/network
	}
	body, _ := json.Marshal(map[string]string{
		"username": c.cfg.Auth.Username,
		"password": c.cfg.Auth.Password,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.BaseURL+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("unifi: login request: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body) //nolint:errcheck // drain for connection reuse
	if resp.StatusCode != http.StatusOK {
		// Note: do not include the response body; it may echo submitted values.
		return fmt.Errorf("unifi: login failed: HTTP %d (check credentials; a cloud SSO account with MFA returns 401)", resp.StatusCode)
	}
	c.loggedIn = true
	return nil
}

// get performs an authenticated GET against a private-API path under the site,
// returning the raw body. It logs in first if needed.
func (c *Client) get(ctx context.Context, apiPath string) ([]byte, error) {
	if err := c.login(ctx); err != nil {
		return nil, err
	}
	url := c.cfg.BaseURL + c.cfg.PathPrefix + apiPath
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if c.cfg.Auth.usesAPIKey() {
		req.Header.Set("X-API-KEY", c.cfg.Auth.APIKey)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("unifi: GET %s: %w", apiPath, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20)) // cap at 32 MiB
	if err != nil {
		return nil, fmt.Errorf("unifi: read %s: %w", apiPath, err)
	}
	if resp.StatusCode == http.StatusUnauthorized && !c.cfg.Auth.usesAPIKey() {
		// Session may have expired; force a re-login on next call.
		c.loggedIn = false
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unifi: GET %s: HTTP %d", apiPath, resp.StatusCode)
	}
	return data, nil
}

// siteAPI builds a private-API path scoped to the configured site.
func (c *Client) siteAPI(suffix string) string {
	return "/api/s/" + c.cfg.Site + suffix
}

// fetchClients returns active client records (stat/sta).
func (c *Client) fetchClients(ctx context.Context) ([]clientDTO, error) {
	body, err := c.get(ctx, c.siteAPI("/stat/sta"))
	if err != nil {
		return nil, err
	}
	var out []clientDTO
	return out, decodeData(body, &out)
}

// fetchDevices returns UniFi device records (stat/device).
func (c *Client) fetchDevices(ctx context.Context) ([]deviceDTO, error) {
	body, err := c.get(ctx, c.siteAPI("/stat/device"))
	if err != nil {
		return nil, err
	}
	var out []deviceDTO
	return out, decodeData(body, &out)
}

// fetchNetworks returns configured networks (rest/networkconf).
func (c *Client) fetchNetworks(ctx context.Context) ([]networkDTO, error) {
	body, err := c.get(ctx, c.siteAPI("/rest/networkconf"))
	if err != nil {
		return nil, err
	}
	var out []networkDTO
	return out, decodeData(body, &out)
}
