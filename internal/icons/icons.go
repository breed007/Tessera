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
	case has(dm, "proxmox"):
		return "proxmox"
	case has(dm, "truenas", "freenas"):
		return "truenas"
	case has(dm, "openmediavault", "omv"):
		return "openmediavault"
	case has(dm, "unraid"):
		return "unraid"
	case has(dm, "docker", "portainer"):
		return "docker"
	case has(dm, "vmware", "esxi", "hypervisor", "qemu", "virtual machine"), has(v, "vmware"):
		return "virtualization"
	case has(dm, "pfsense"):
		return "pfsense"
	case has(dm, "opnsense"):
		return "opnsense"
	case has(dm, "fortinet", "fortigate", "fortios"), has(v, "fortinet"):
		return "fortinet"
	case has(dm, "openwrt", "dd-wrt", "ddwrt"):
		return "openwrt"
	case has(d, "firewall"):
		return "firewall"
	case has(dm, "pi-hole", "pihole", "adguard"):
		return "adblock"
	case has(dm, "home assistant", "homeassistant", "hass.io", "hassio"):
		return "homeassistant"
	case has(dm, "cloudflare"):
		return "cloud"
	case has(dm, "splunk", "elastic", "logstash", "kibana", "graylog"):
		return "analytics"
	case has(dm, "plex"):
		return "plex"
	case has(dm, "jellyfin"):
		return "jellyfin"
	case has(dm, "kodi", "libreelec", "osmc"):
		return "kodi"
	case has(dm, "emby", "media server"):
		return "media-server"
	case has(dm, "roku"):
		return "roku"
	case has(dm, "sonos"), has(v, "sonos"):
		return "sonos"
	case has(dm, "shelly"), has(v, "shelly"):
		return "shelly"
	case has(dm, "philips hue", "hue bridge"), has(v, "signify"):
		return "philipshue"
	case has(dm, "lifx"), has(v, "lifx"):
		return "lifx"
	case has(dm, "wemo"), has(v, "belkin"):
		return "wemo"
	case has(dm, "smartthings"):
		return "smartthings"
	case has(dm, "doorbell"):
		return "doorbell"
	case has(dm, "esp32", "esp8266", "espressif", "microcontroller", "arduino"), has(v, "espressif", "arduino"):
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
		return "tplink"
	case has(v, "netgear"):
		return "netgear"
	case has(v, "asus"): // covers ASUSTeK
		return "asus"
	case has(v, "mikrotik", "mikrotikls", "routerboard"):
		return "mikrotik"
	case has(v, "roku"):
		return "roku"
	case has(v, "cisco"):
		return "cisco"
	case has(v, "huawei"):
		return "huawei"
	case has(v, "nvidia"):
		return "nvidia"
	case has(v, "lg electronics", "lg innotek"):
		return "lg"
	case has(v, "sony"):
		return "sony"
	case has(v, "panasonic"):
		return "panasonic"
	case has(v, "xiaomi"):
		return "xiaomi"
	case has(v, "dell"):
		return "dell"
	case has(v, "hewlett", "hpe", "hp inc"):
		return "hp"
	case has(v, "lenovo"):
		return "lenovo"
	case has(v, "qnap"):
		return "qnap"
	case has(v, "acer"):
		return "acer"
	case has(v, "framework"):
		return "framework"
	case has(v, "super micro", "supermicro"):
		return "supermicro"
	case has(v, "ring llc"):
		return "ring"
	case has(v, "wyze"):
		return "wyze"
	case has(v, "oneplus"):
		return "oneplus"
	case has(v, "oppo"):
		return "oppo"
	case has(v, "motorola"):
		return "motorola"
	case has(v, "nokia"):
		return "nokia"
	case has(v, "epson"):
		return "epson"
	case has(v, "philips"): // home networks: typically a Hue bridge/bulb
		return "philipshue"
	case has(v, "texas instruments"):
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
