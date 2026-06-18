package icons

import "testing"

func TestAuto(t *testing.T) {
	cases := []struct{ vendor, os, dc, model, want string }{
		{"Ubiquiti Networks", "", "UniFi Switch", "", "ubiquiti"},
		{"Raspberry Pi Foundation", "", "Single-Board Computer", "", "raspberrypi"},
		{"", "Windows 10", "", "", "microsoft"},
		{"", "Linux 5.10", "", "", "linux"},
		{"Apple", "", "", "", "apple"},
		{"", "", "NAS", "", "nas"},
		{"", "", "IP Camera", "", "camera"},
		{"Unknown Vendor", "", "", "", "unknown"},
		// Specific products/roles (often in the model field) → the new icons.
		{"Intel Corporate", "Linux", "computer", "Proxmox", "virtualization"},
		{"", "", "router / gateway", "pfSense", "firewall"},
		{"", "", "", "OPNsense", "firewall"},
		{"Fortinet, Inc.", "", "", "FortiGate 60F", "firewall"},
		{"eero inc.", "", "", "eero Pro 6", "access-point"},
		{"", "", "computer", "Pi-hole", "adblock"},
		{"", "", "", "AdGuard Home", "adblock"},
		{"", "", "computer", "Splunk Enterprise", "analytics"},
		{"", "", "media server", "Plex Media Server", "media-server"},
		{"Ring LLC", "", "camera", "Ring Video Doorbell Pro", "doorbell"},
		{"", "", "IoT device", "Espressif ESP32", "microcontroller"},
		{"Espressif Inc.", "", "", "", "microcontroller"},
		{"", "", "", "Chamberlain MyQ Garage Door Opener", "garage"},
		{"", "", "", "HomeLabs Dehumidifier", "dehumidifier"},
		{"VMware, Inc.", "", "", "", "virtualization"},
		// A Ring floodlight cam (no "doorbell") still → camera.
		{"Ring LLC", "", "camera", "Ring Floodlight Cam", "camera"},
	}
	for _, c := range cases {
		if got := Auto(c.vendor, c.os, c.dc, c.model); got != c.want {
			t.Errorf("Auto(%q,%q,%q,%q) = %q, want %q", c.vendor, c.os, c.dc, c.model, got, c.want)
		}
	}
}
