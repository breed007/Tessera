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
	"strings"
	"time"
)

// Config is the connection to a Proxmox VE node/cluster. The API token is the
// full "user@realm!tokenid=secret" string (created under Datacenter → API Tokens,
// read-only Privilege Separation is fine — grant PVEAuditor on /).
type Config struct {
	BaseURL   string // e.g. https://proxmox.lan:8006
	Token     string // PVEAPIToken value: user@realm!tokenid=uuid
	VerifyTLS bool   // PVE ships a self-signed cert; usually false
}

// Client performs authenticated GETs against the PVE API. Read-only.
type Client struct {
	cfg  Config
	http *http.Client
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
// out.
func (c *Client) get(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.cfg.BaseURL+"/api2/json"+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "PVEAPIToken="+c.cfg.Token)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("proxmox: 401 — check the API token and that it has PVEAuditor on /")
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
