package active

import (
	"context"
	"net/http"
	"net/http/httptest"
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
