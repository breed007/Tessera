package active

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"strings"
	"time"
)

// Proxmox VE identity and version from the unauthenticated login page on 8006
// (ported from IP Recon 1.5).
//
// TWO PROBLEMS, ONE ENDPOINT.
//
//  1. INCONSISTENT IDENTIFICATION. Proxmox VE *is* Debian underneath, so both
//     "Proxmox VE" and "Debian Linux" are true statements about the same host —
//     and which one won varied per scan. IP Recon had three identical
//     hypervisors report as Proxmox, Proxmox and "Debian Linux 13" in a single
//     run. A positive, deterministic Proxmox signal settles it, and the more
//     specific answer is the right one: every Proxmox host is a Debian host,
//     almost no Debian host is a Proxmox host.
//
//  2. NO VERSION. `/api2/json/version` needs authentication. But the login page
//     — served to anyone — carries the version in the cache-busting query on its
//     own JavaScript bundle:
//
//     <title>pve1 - Proxmox Virtual Environment</title>
//     <script src="/pve2/js/pvemanagerlib.js?ver=9.2.5">
//
//     Measured on two hypervisors (2026-08-14): both HTTP 200, 2,828 bytes,
//     `ver=9.2.5`. That parameter is how the UI busts its own cache on upgrade,
//     so it necessarily tracks the installed version.
//
// Read-only and unauthenticated (§4.1): one GET of a login page, no credentials,
// no API call. This is complementary to the Proxmox collector, which inventories
// guests through the authenticated API — this identifies the HOST from outside,
// with no token configured.

// proxmoxFindings is what the login page stated.
type proxmoxFindings struct {
	version  string // "9.2.5"
	nodeName string // "pve1"
}

// probeProxmoxVE fetches https://host:8006/ and reads the identity, version and
// node name. Returns nil unless the page actually identifies itself as Proxmox —
// a bare 200 on 8006 is not enough, since anything could be listening there.
func probeProxmoxVE(ctx context.Context, host string, client *http.Client) *proxmoxFindings {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+host+":8006/", nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Connection", "close")
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	return parseProxmoxPage(string(b))
}

// parseProxmoxPage extracts what the login page states. Split out from the
// request so it can be exercised against the real page's shape without a
// network.
func parseProxmoxPage(body string) *proxmoxFindings {
	// Identity first. Without this, any 8006 listener would be labelled a
	// hypervisor on the strength of a port number.
	if !strings.Contains(body, "Proxmox Virtual Environment") {
		return nil
	}
	return &proxmoxFindings{
		version:  proxmoxVersion(body),
		nodeName: proxmoxNode(body),
	}
}

func proxmoxVersion(body string) string {
	const marker = "pvemanagerlib.js?ver="
	i := strings.Index(body, marker)
	if i < 0 {
		return ""
	}
	rest := body[i+len(marker):]
	end := 0
	for end < len(rest) && (rest[end] == '.' || (rest[end] >= '0' && rest[end] <= '9')) {
		end++
	}
	v := rest[:end]
	// Require at least major.minor, so a stray "ver=9" cannot pass as a version
	// and a truncated read cannot end on a dot.
	if !strings.Contains(v, ".") || strings.HasSuffix(v, ".") {
		return ""
	}
	return v
}

func proxmoxNode(body string) string {
	i := strings.Index(body, "<title>")
	if i < 0 {
		return ""
	}
	rest := body[i+len("<title>"):]
	j := strings.Index(rest, "</title>")
	if j < 0 {
		return ""
	}
	title := rest[:j]
	dash := strings.Index(title, " - ")
	if dash < 0 {
		return ""
	}
	return strings.TrimSpace(title[:dash])
}

// newSelfSignedClient builds an HTTP client that accepts the self-signed
// certificate Proxmox ships by default.
//
// Scoped to this probe so it cannot loosen trust for anything else, and the
// request reads a version string rather than making a trust decision. Redirects
// are refused: a redirect off the host would take an unverified-TLS client
// somewhere we never chose to go.
func newSelfSignedClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // see doc comment
			DisableKeepAlives: true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}
