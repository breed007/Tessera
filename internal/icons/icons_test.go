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
		{"Intel Corporate", "Linux", "computer", "Proxmox", "proxmox"},
		{"", "", "router / gateway", "pfSense", "pfsense"},
		{"", "", "", "OPNsense", "opnsense"},
		{"Fortinet, Inc.", "", "", "FortiGate 60F", "fortinet"},
		{"", "", "firewall appliance", "", "firewall"}, // generic firewall, unknown vendor
		{"eero inc.", "", "", "eero Pro 6", "access-point"},
		// Networking vendor brands.
		{"TP-LINK TECHNOLOGIES CO.,LTD.", "", "router", "", "tplink"},
		{"NETGEAR", "", "access point", "", "netgear"},
		{"ASUSTek COMPUTER INC.", "", "router", "", "asus"},
		{"Routerboard.com", "", "", "MikroTik hAP ax3", "mikrotik"},
		{"Cisco Systems, Inc", "", "switch", "", "cisco"},
		// Homelab OS / appliances (live in the model field).
		{"", "Linux", "server", "Proxmox VE", "proxmox"},
		{"", "", "NAS", "TrueNAS Scale", "truenas"},
		{"", "", "server", "Home Assistant", "homeassistant"},
		{"", "", "server", "Docker host", "docker"},
		// Smart-home + media brands.
		{"Sonos, Inc.", "", "speaker", "", "sonos"},
		{"Signify B.V.", "", "", "Philips Hue Bridge", "philipshue"},
		{"Roku, Inc.", "", "media", "", "roku"},
		{"", "", "media", "Plex Media Server", "plex"},
		{"", "", "media", "Jellyfin", "jellyfin"},
		{"Ring LLC", "", "camera", "Ring Floodlight Cam", "ring"},
		// Computing / NAS vendors (note short-token safety: hp via "hewlett", lg via "lg electronics").
		{"Dell Inc.", "", "server", "", "dell"},
		{"Hewlett Packard", "", "printer", "", "hp"},
		{"LG Electronics", "", "tv", "", "lg"},
		{"QNAP Systems, Inc.", "", "nas", "", "qnap"},
		{"OnePlus Technology", "", "phone", "", "oneplus"},
		// Short-token false-positive guard: a camera vendor containing no brand token
		// must not mis-map; e.g. a generic "Vivotek" must NOT become a phone.
		{"VIVOTEK Inc.", "", "camera", "", "camera"},
		{"", "", "computer", "Pi-hole", "adblock"},
		{"", "", "", "AdGuard Home", "adblock"},
		{"", "", "computer", "Splunk Enterprise", "analytics"},
		{"", "", "media server", "Plex Media Server", "plex"},
		{"", "", "media server", "Emby Server", "media-server"},
		{"Ring LLC", "", "camera", "Ring Video Doorbell Pro", "doorbell"},
		{"", "", "IoT device", "Espressif ESP32", "microcontroller"},
		{"Espressif Inc.", "", "", "", "microcontroller"},
		{"", "", "", "Chamberlain MyQ Garage Door Opener", "garage"},
		{"", "", "", "HomeLabs Dehumidifier", "dehumidifier"},
		{"VMware, Inc.", "", "", "", "virtualization"},
	}
	for _, c := range cases {
		if got := Auto(c.vendor, c.os, c.dc, c.model); got != c.want {
			t.Errorf("Auto(%q,%q,%q,%q) = %q, want %q", c.vendor, c.os, c.dc, c.model, got, c.want)
		}
	}
}
