package active

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"howett.net/plist"
)

// Media-device HTTP identity probes, ported from IP Recon (AirPlayProbe /
// GoogleCastProbe). Both are unauthenticated, read-only HTTP GETs against a
// well-known local port and yield an exact model + name — the strongest device
// tell short of a login. SPAN-free: a direct connection to the host.

// mediaFindings is what a media identity probe surfaced.
type mediaFindings struct {
	deviceClass string
	os          string
	model       string
	name        string
}

func (m mediaFindings) empty() bool {
	return m.deviceClass == "" && m.os == "" && m.model == "" && m.name == ""
}

// probeAirPlay queries an AirPlay responder's /info endpoint (TCP 49152) for its
// identity plist. Apple TV, HomePod, iPhone, iPad, and Mac all answer. Returns
// empty findings when the host isn't AirPlay or the body is unparseable.
func probeAirPlay(ctx context.Context, host string, client *http.Client) mediaFindings {
	for _, path := range []string{"/info", "/server-info"} {
		body, server, ok := airplayGet(ctx, host, path, client)
		if !ok {
			continue
		}
		f := mediaFindings{}
		var doc map[string]any
		if _, err := plist.Unmarshal(body, &doc); err == nil {
			f.model = str(doc["model"])
			f.name = str(doc["name"])
			f.os = osFromApple(str(doc["model"]), str(doc["osVersion"]))
		}
		f.deviceClass, f.os = classifyAppleModel(f.model, f.os, server)
		if !f.empty() {
			return f
		}
	}
	return mediaFindings{}
}

func airplayGet(ctx context.Context, host, path string, client *http.Client) (body []byte, server string, ok bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+host+":49152"+path, nil)
	if err != nil {
		return nil, "", false
	}
	// Mimic an Apple client so firmware that rejects unknown clients still answers.
	req.Header.Set("User-Agent", "AirPlay/1")
	req.Header.Set("Connection", "close")
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", false
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, "", false
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	return b, resp.Header.Get("Server"), len(b) > 0
}

// classifyAppleModel derives a device class from an AirPlay model identifier and,
// when the plist gave no osVersion, from the AirTunes server string.
func classifyAppleModel(model, os, server string) (dev, outOS string) {
	m := strings.ToLower(model)
	switch {
	case strings.HasPrefix(m, "appletv"):
		return "media / TV device", pick(os, "tvOS")
	case strings.HasPrefix(m, "audioaccessory"):
		return "speaker", os // HomePod
	case strings.HasPrefix(m, "iphone"), strings.HasPrefix(m, "ipod"):
		return "Apple mobile device", pick(os, "iOS")
	case strings.HasPrefix(m, "ipad"):
		return "Apple mobile device", pick(os, "iPadOS")
	case strings.HasPrefix(m, "mac"):
		return "computer", pick(os, "macOS")
	}
	// No model in the body — a plain AirPlay/AirTunes speaker (receiver).
	if server != "" || model == "" {
		return "media / TV device", os
	}
	return "", os
}

func osFromApple(model, osVersion string) string {
	if osVersion == "" {
		return ""
	}
	m := strings.ToLower(model)
	switch {
	case strings.HasPrefix(m, "appletv"):
		return "tvOS " + osVersion
	case strings.HasPrefix(m, "ipad"):
		return "iPadOS " + osVersion
	case strings.HasPrefix(m, "iphone"), strings.HasPrefix(m, "ipod"):
		return "iOS " + osVersion
	case strings.HasPrefix(m, "mac"):
		return "macOS " + osVersion
	}
	return osVersion
}

// probeGoogleCast queries the Google Cast eureka_info endpoint (TCP 8008) for
// device identity. Chromecast, Nest Hub/Mini/Audio, Google Home, and Nest Cam
// all answer this unauthenticated JSON endpoint.
func probeGoogleCast(ctx context.Context, host string, client *http.Client) mediaFindings {
	return probeGoogleCastAt(ctx, "http://"+host+":8008", client)
}

func probeGoogleCastAt(ctx context.Context, base string, client *http.Client) mediaFindings {
	for _, path := range []string{"/setup/eureka_info", "/setup/device_info"} {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+path, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			continue
		}
		var doc map[string]any
		if err := json.Unmarshal(body, &doc); err != nil {
			continue
		}
		f := mediaFindings{
			model: pick(str(doc["model_name"]), str(doc["model"])),
			name:  pick(str(doc["name"]), str(doc["device_name"])),
		}
		if f.model != "" || f.name != "" {
			f.deviceClass = classifyCastModel(f.model)
			return f
		}
	}
	return mediaFindings{}
}

// classifyCastModel buckets a Cast model_name into a device class.
func classifyCastModel(model string) string {
	m := strings.ToLower(model)
	switch {
	case strings.Contains(m, "chromecast"), strings.Contains(m, "android tv"), strings.Contains(m, "google tv"):
		return "media / TV device"
	case strings.Contains(m, "nest hub"), strings.Contains(m, "home hub"):
		return "smart display"
	case strings.Contains(m, "nest audio"), strings.Contains(m, "nest mini"), strings.Contains(m, "home mini"),
		strings.Contains(m, "google home"), strings.Contains(m, "nest wifi point"):
		return "speaker"
	case strings.Contains(m, "nest cam"), strings.Contains(m, "nest doorbell"):
		return "camera"
	case strings.Contains(m, "nest"):
		return "IoT device"
	}
	return "media / TV device" // any Cast responder is at least a media endpoint
}

// ── helpers ──────────────────────────────────────────────────────────────────

func str(v any) string {
	s, _ := v.(string)
	return strings.TrimSpace(s)
}

func pick(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
