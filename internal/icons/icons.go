// Package icons maps a discovered device's signals (vendor, OS guess, device
// class) to a bundled icon id (§M12). It is the auto-assignment used when an
// operator hasn't picked an icon by hand. Pure and testable.
package icons

import "strings"

// Default is the fallback icon id when nothing matches.
const Default = "unknown"

// Auto returns the best icon id for a device. Order: specific product/role
// (most meaningful), then vendor brand, then OS, then device type, then the
// generic fallback. model is the precise hardware model (often where a product
// name like "Espressif ESP32" or "Proxmox" actually lands).
func Auto(vendor, osGuess, deviceClass, model string) string {
	v, o, d := strings.ToLower(vendor), strings.ToLower(osGuess), strings.ToLower(deviceClass)
	dm := strings.ToLower(deviceClass + " " + model) // class + model, for product matching

	// Specific product / role / appliance — checked first so e.g. "media server"
	// doesn't fall through to the generic TV icon, or a Proxmox box to its NIC
	// vendor. Matched against class+model.
	switch {
	case has(dm, "vmware", "esxi", "proxmox", "hypervisor", "qemu", "virtual machine"), has(v, "vmware"):
		return "virtualization"
	case has(dm, "pfsense", "opnsense", "fortinet", "fortigate"), has(v, "fortinet"), has(d, "firewall"):
		return "firewall"
	case has(dm, "pi-hole", "pihole", "adguard"):
		return "adblock"
	case has(dm, "cloudflare"):
		return "cloud"
	case has(dm, "splunk", "elastic", "logstash", "kibana", "graylog"):
		return "analytics"
	case has(dm, "plex", "jellyfin", "emby", "media server"):
		return "media-server"
	case has(dm, "doorbell"):
		return "doorbell"
	case has(dm, "esp32", "esp8266", "espressif", "microcontroller"), has(v, "espressif"):
		return "microcontroller"
	case has(dm, "myq", "garage", "liftmaster", "chamberlain"):
		return "garage"
	case has(dm, "dishwasher"):
		return "dishwasher"
	case has(dm, "washer", "washing machine"):
		return "washer"
	case has(dm, "dryer"):
		return "dryer"
	case has(dm, "oven", "stove", "cooktop"):
		return "oven"
	case has(dm, "dehumidifier", "humidifier"):
		return "dehumidifier"
	}

	// Vendor brand.
	switch {
	case has(v, "ubiquiti", "unifi"):
		return "ubiquiti"
	case has(v, "apple"):
		return "apple"
	case has(v, "raspberry"):
		return "raspberrypi"
	case has(v, "synology"):
		return "synology"
	case has(v, "microsoft"):
		return "microsoft"
	case has(v, "intel"):
		return "intel"
	case has(v, "samsung"):
		return "samsung"
	case has(v, "google", "nest"):
		return "google"
	case has(v, "eero"):
		return "access-point" // mesh Wi-Fi node
	case has(v, "amazon"):
		return "amazon"
	case has(v, "tp-link", "tplink"):
		return "router"
	case has(v, "philips", "sonos", "texas instruments"):
		return "iot"
	}

	// Operating system.
	switch {
	case has(o, "windows"), has(d, "windows"):
		return "microsoft"
	case has(o, "macos", "mac os", "ios", "ipad", "iphone"):
		return "apple"
	case has(o, "android"):
		return "android"
	case has(o, "ubuntu"):
		return "ubuntu"
	case has(o, "debian"):
		return "debian"
	case has(o, "linux"):
		return "linux"
	}

	// Device class / type.
	switch {
	case has(d, "switch"):
		return "switch"
	case has(d, "access point", "accesspoint", " ap", "wifi", "wireless"):
		return "access-point"
	case has(d, "gateway", "router", "firewall"):
		return "router"
	case has(d, "nas", "storage"):
		return "nas"
	case has(d, "single-board", "sbc"):
		return "raspberrypi"
	case has(d, "server"):
		return "server"
	case has(d, "printer"):
		return "printer"
	case has(d, "camera", "nvr", "cctv"):
		return "camera"
	case has(d, "tv", "television", "media", "chromecast", "roku"):
		return "tv"
	case has(d, "phone", "mobile", "smartphone"):
		return "mobile"
	case has(d, "tablet"):
		return "tablet"
	case has(d, "laptop", "notebook"):
		return "laptop"
	case has(d, "desktop", "workstation", "pc"):
		return "desktop"
	case has(d, "iot", "sensor", "bulb", "light", "plug", "thermostat"):
		return "iot"
	}
	return Default
}

func has(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
