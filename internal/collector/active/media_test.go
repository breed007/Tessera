package active

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestClassifyCastModel(t *testing.T) {
	cases := map[string]string{
		"Chromecast":             "media / TV device",
		"Chromecast Ultra":       "media / TV device",
		"Google Nest Hub":        "smart display",
		"Nest Audio":             "speaker",
		"Google Home Mini":       "speaker",
		"Nest Cam (indoor)":      "camera",
		"Google Nest Thermostat": "IoT device",
		"Some New Cast Gadget":   "media / TV device",
	}
	for model, want := range cases {
		if got := classifyCastModel(model); got != want {
			t.Errorf("classifyCastModel(%q) = %q, want %q", model, got, want)
		}
	}
}

func TestClassifyAppleModel(t *testing.T) {
	cases := []struct {
		model, os, server string
		wantDev           string
	}{
		{"AppleTV14,1", "", "", "media / TV device"},
		{"AudioAccessory5,1", "", "", "speaker"},
		{"iPhone15,2", "", "", "Apple mobile device"},
		{"iPad13,1", "", "", "Apple mobile device"},
		{"MacBookPro18,1", "", "", "computer"},
		{"", "", "AirTunes/770.8.1", "media / TV device"}, // bare AirPlay speaker
	}
	for _, c := range cases {
		if dev, _ := classifyAppleModel(c.model, c.os, c.server); dev != c.wantDev {
			t.Errorf("classifyAppleModel(%q,_,%q) dev = %q, want %q", c.model, c.server, dev, c.wantDev)
		}
	}
}

func TestProbeGoogleCast(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/setup/eureka_info" {
			w.WriteHeader(404)
			return
		}
		w.Write([]byte(`{"name":"Living Room","model_name":"Chromecast Ultra","manufacturer":"Google Inc."}`))
	}))
	defer srv.Close()

	// The probe targets :8008; point it at the test server's host:port instead.
	host := strings.TrimPrefix(srv.URL, "http://")
	f := probeGoogleCastAt(context.Background(), "http://"+host, srv.Client())
	if f.name != "Living Room" || f.model != "Chromecast Ultra" {
		t.Fatalf("got %+v", f)
	}
	if f.deviceClass != "media / TV device" {
		t.Errorf("deviceClass = %q", f.deviceClass)
	}
}

// A Mac answers /info on 7000 and an iOS device on 49152. Hardcoding 49152 is
// why this probe returned nothing for every Mac on the network, so the port
// walk is the behaviour worth pinning.
func TestProbeAirPlayWalksPorts(t *testing.T) {
	// A "Mac" that answers only on its own port, 404 on anything else.
	var hitPaths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hitPaths = append(hitPaths, r.URL.Path)
		if r.URL.Path != "/info" {
			w.WriteHeader(404)
			return
		}
		// Minimal XML plist: a Mac states a build, never an osVersion.
		w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>model</key><string>Mac16,8</string>
<key>name</key><string>studiombp14</string>
<key>osBuildVersion</key><string>25G76</string>
</dict></plist>`))
	}))
	defer srv.Close()

	host, portStr, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(portStr)

	// A closed port ahead of the live one must not stop the walk.
	f := probeAirPlay(context.Background(), host, []int{1, port}, srv.Client())
	if f.model != "Mac16,8" {
		t.Fatalf("model = %q, want Mac16,8 (walk stopped at the closed port?)", f.model)
	}
	if f.osVersion != "26.6" {
		t.Errorf("osVersion = %q, want 26.6 derived from build 25G76", f.osVersion)
	}
	if f.os != "macOS" || f.deviceClass != "computer" {
		t.Errorf("os/class = %q/%q, want macOS/computer", f.os, f.deviceClass)
	}
	if len(hitPaths) == 0 || hitPaths[0] != "/info" {
		t.Errorf("expected /info to be tried first, got %v", hitPaths)
	}
}

// The candidate list is the measured one, in the measured order: a Mac answers
// on 7000, so trying 49152 first costs every Mac an extra round trip.
func TestAirPlayPortOrder(t *testing.T) {
	if len(airplayPorts) == 0 || airplayPorts[0] != 7000 {
		t.Errorf("airplayPorts = %v, want 7000 first (the measured Mac port)", airplayPorts)
	}
	want := map[int]bool{7000: true, 49152: true, 5000: true}
	for _, p := range airplayPorts {
		if !want[p] {
			t.Errorf("unexpected AirPlay candidate port %d", p)
		}
		delete(want, p)
	}
	for p := range want {
		t.Errorf("missing AirPlay candidate port %d", p)
	}
}

// orderByOpen decides what to try FIRST, never what to try at all — an operator
// who trimmed the scanned-port list must not thereby lose the identification.
func TestOrderByOpenKeepsEveryCandidate(t *testing.T) {
	cands := []int{7000, 49152, 5000}

	got := orderByOpen(cands, map[int]bool{49152: true})
	if len(got) != 3 || got[0] != 49152 {
		t.Errorf("orderByOpen = %v, want the open port first and all three kept", got)
	}

	// Nothing open (or no scan at all): the order is unchanged, nothing dropped.
	if got := orderByOpen(cands, nil); len(got) != 3 || got[0] != 7000 {
		t.Errorf("orderByOpen with no open ports = %v, want the candidates unchanged", got)
	}
}
