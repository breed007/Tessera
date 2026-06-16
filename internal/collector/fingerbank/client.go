package fingerbank

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// defaultEndpoint is the verified Fingerbank interrogate endpoint (§7). IP Recon
// uses POST with a JSON body and the key as a query parameter.
const defaultEndpoint = "https://api.fingerbank.org/api/v2/combinations/interrogate"

// errRateLimited signals an HTTP 429 (or treated-as-rate-limited 5xx) so the
// governor can back off rather than the caller spin-retrying.
var errRateLimited = errors.New("fingerbank: rate limited")

// doer is the minimal HTTP surface the client needs (http.Client satisfies it),
// injectable for tests.
type doer interface {
	Do(*http.Request) (*http.Response, error)
}

type client struct {
	http     doer
	endpoint string
	key      string
}

// apiRequest matches Fingerbank's interrogate body.
type apiRequest struct {
	SrcMAC          string   `json:"src_mac_address,omitempty"`
	DHCPFingerprint string   `json:"dhcp_fingerprint,omitempty"`
	DHCPVendor      string   `json:"dhcp_vendor,omitempty"`
	Hostname        string   `json:"hostname,omitempty"`
	UserAgents      []string `json:"user_agents,omitempty"`
}

// apiResponse matches the fields we use from the interrogate response.
type apiResponse struct {
	Device struct {
		Name         string `json:"name"`
		ParentDevice *struct {
			Name string `json:"name"`
		} `json:"parent_device"`
	} `json:"device"`
	Score   int    `json:"score"`
	Version string `json:"version"`
}

// interrogate performs one classification request. It maps HTTP status to the
// caller's contract: 200 → verdict, 404 → not-found (still a valid answer),
// 429/5xx → errRateLimited (governor backs off), other → error.
func (c *client) interrogate(ctx context.Context, sig Signature) (Verdict, error) {
	body, err := json.Marshal(apiRequest{
		SrcMAC:          sig.MAC,
		DHCPFingerprint: sig.DHCPFingerprint,
		DHCPVendor:      sig.DHCPVendor,
		Hostname:        sig.Hostname,
		UserAgents:      sig.UserAgents,
	})
	if err != nil {
		return Verdict{}, err
	}
	u := c.endpoint + "?key=" + url.QueryEscape(c.key)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return Verdict{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return Verdict{}, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	switch {
	case resp.StatusCode == http.StatusOK:
		return parseVerdict(data)
	case resp.StatusCode == http.StatusNotFound:
		return Verdict{Found: false}, nil
	case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
		return Verdict{}, errRateLimited
	default:
		return Verdict{}, fmt.Errorf("fingerbank: HTTP %d", resp.StatusCode)
	}
}

func parseVerdict(data []byte) (Verdict, error) {
	var r apiResponse
	if err := json.Unmarshal(data, &r); err != nil {
		return Verdict{}, fmt.Errorf("fingerbank: decode response: %w", err)
	}
	name := strings.TrimSpace(r.Device.Name)
	if name == "" {
		return Verdict{Found: false}, nil
	}
	class := name
	if r.Device.ParentDevice != nil && r.Device.ParentDevice.Name != "" {
		class = r.Device.ParentDevice.Name + "/" + name
	}
	return Verdict{Found: true, DeviceClass: class, Score: clampScore(r.Score)}, nil
}

func clampScore(s int) int {
	if s < 0 {
		return 0
	}
	if s > 100 {
		return 100
	}
	return s
}
