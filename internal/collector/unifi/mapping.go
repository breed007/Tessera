package unifi

import (
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/breed007/Tessera/internal/observation"
)

// emit is one observation the poller will record (source is always unifi). Pure
// mapping produces these from controller JSON; the poller stamps the source,
// timestamp, and collector id and writes them through the standard Sink. Keeping
// the mapping pure makes it testable against captured controller JSON without a
// live controller.
type emit struct {
	subjectType observation.SubjectType
	subject     string
	attr        observation.Attribute
	value       string
	confidence  int
}

// Confidence levels for UniFi-sourced observations. Port↔MAC and IP bindings are
// first-party L2 facts (ground tier); fingerprints are merely strong/inferential.
const (
	confBinding     = 90
	confHostname    = 85
	confSwitchPort  = 95
	confVLAN        = 90
	confOUI         = 80
	confDeviceClass = 75
	confSubnet      = 95
	confFirmware    = 90 // first-party fact straight from the controller
	confUniFiModel  = 85 // controller-reported gear model (mDNS self-report still outranks it)
	confDHCP        = 90 // DHCP lease class straight from the controller
	// OS derived from a fingerprinted model name — a notch below the model itself,
	// which is the directly-reported fact.
	confFingerprintOS = 70
)

// mapClients turns client records into observations: MAC↔IP binding, hostname,
// vendor, switch port↔MAC (topology), VLAN membership, and the UniFi device
// fingerprint (→ device class + OS).
func mapClients(clients []clientDTO) []emit {
	var out []emit
	for _, c := range clients {
		mac := strings.TrimSpace(c.MAC)
		if mac == "" {
			continue
		}
		ip := strings.TrimSpace(c.IP)
		if ip == "" && c.UseFixedIP {
			ip = strings.TrimSpace(c.FixedIP)
		}
		if ip != "" {
			out = append(out, emit{observation.SubjectMAC, mac, observation.AttrIPBinding, ip, confBinding})
			// The controller knows whether this IP is a static reservation or a
			// dynamic lease — surface it on the address.
			styp := observation.SubjectIPv4
			if strings.Contains(ip, ":") {
				styp = observation.SubjectIPv6
			}
			class := "dynamic"
			if c.UseFixedIP {
				class = "reserved"
			}
			out = append(out, emit{styp, ip, observation.AttrDHCPLease, class, confDHCP})
		}
		if name := firstNonEmpty(c.Name, c.Hostname); name != "" {
			out = append(out, emit{observation.SubjectMAC, mac, observation.AttrHostname, name, confHostname})
		}
		if c.OUI != "" {
			out = append(out, emit{observation.SubjectMAC, mac, observation.AttrOUIVendor, c.OUI, confOUI})
		}
		switch {
		case c.SwMAC != "" && c.SwPort.Set:
			// value encoding consumed by the reconciler: "<switch-mac>/<port-idx>".
			val := fmt.Sprintf("%s/%d", c.SwMAC, c.SwPort.Val)
			out = append(out, emit{observation.SubjectMAC, mac, observation.AttrSwitchPort, val, confSwitchPort})
		case c.APMac != "":
			// Wireless client → nests under its access point.
			out = append(out, emit{observation.SubjectMAC, mac, observation.AttrSwitchPort, c.APMac + "/wifi", confSwitchPort})
		}
		if c.VLAN.Set {
			out = append(out, emit{observation.SubjectMAC, mac, observation.AttrVLANMembership, strconv.Itoa(c.VLAN.Val), confVLAN})
		}
		// First-party device fingerprint: UniFi already matched this client against
		// its device database. The dev_id name is a hardware model → emit it as the
		// model (mDNS self-report outranks it), plus an OS where the name is clear.
		// Note: UniFi's fingerprint is partly icon/association-based, so it's a
		// fallback below the device's own mDNS report.
		if model, ok := resolveDeviceModel(c.DevID, c.DevIDOverride); ok {
			out = append(out, emit{observation.SubjectMAC, mac, observation.AttrModel, model, confDeviceClass})
			if os := osFromModel(model); os != "" {
				out = append(out, emit{observation.SubjectMAC, mac, observation.AttrOSGuess, os, confFingerprintOS})
			}
		}
	}
	return out
}

// mapDevices turns UniFi gear records into observations: binding, hostname, and
// a device_class derived from the device type.
func mapDevices(devices []deviceDTO) []emit {
	var out []emit
	for _, d := range devices {
		mac := strings.TrimSpace(d.MAC)
		if mac == "" {
			continue
		}
		if ip := strings.TrimSpace(d.IP); ip != "" {
			out = append(out, emit{observation.SubjectMAC, mac, observation.AttrIPBinding, ip, confBinding})
		}
		if d.Name != "" {
			out = append(out, emit{observation.SubjectMAC, mac, observation.AttrHostname, d.Name, confHostname})
		}
		// device_class is the coarse class (Access Point / Switch / Gateway); the
		// specific product name goes to the separate model field.
		if dc := deviceClass(d.Type); dc != "" {
			out = append(out, emit{observation.SubjectMAC, mac, observation.AttrDeviceClass, dc, confDeviceClass})
		}
		// Prefer the friendly product name from the bundled DB; if the controller's
		// model code isn't in it, surface the raw code so the model is still shown
		// (and any table gap is visible and reportable). model_display, when the
		// controller provides it, is the most authoritative.
		if disp := strings.TrimSpace(d.ModelDisplay); disp != "" {
			out = append(out, emit{observation.SubjectMAC, mac, observation.AttrModel, disp, confUniFiModel})
		} else if name, ok := resolveUniFiModel(d.Model); ok {
			out = append(out, emit{observation.SubjectMAC, mac, observation.AttrModel, name, confUniFiModel})
		} else if code := strings.TrimSpace(d.Model); code != "" {
			out = append(out, emit{observation.SubjectMAC, mac, observation.AttrModel, code, confUniFiModel})
		}
		if v := strings.TrimSpace(d.Version); v != "" {
			out = append(out, emit{observation.SubjectMAC, mac, observation.AttrFirmware, v, confFirmware})
		}
		// Uplink → the backbone topology (this device hangs off uplink_mac:port at
		// the given speed). Encoded "<parent-mac>/<port>|<mbps>" (speed optional).
		if up := strings.TrimSpace(d.Uplink.MAC); up != "" && d.Uplink.RemotePort.Set {
			val := fmt.Sprintf("%s/%d", up, d.Uplink.RemotePort.Val)
			if d.Uplink.Speed.Set && d.Uplink.Speed.Val > 0 {
				val += fmt.Sprintf("|%d", d.Uplink.Speed.Val)
			}
			out = append(out, emit{observation.SubjectMAC, mac, observation.AttrSwitchPort, val, confSwitchPort})
		}
	}
	return out
}

// mapNetworks turns configured networks into subnet_hint observations that seed
// the subnets table (§4.3). WAN and un-parseable networks are skipped.
func mapNetworks(networks []networkDTO) []emit {
	var out []emit
	for _, n := range networks {
		if strings.EqualFold(n.Purpose, "wan") {
			continue
		}
		gwIP, ipnet, err := net.ParseCIDR(strings.TrimSpace(n.IPSubnet))
		if err != nil || ipnet == nil {
			continue
		}
		hint := observation.SubnetHintValue{
			CIDR:    ipnet.String(),
			Name:    n.Name,
			Gateway: gwIP.String(),
		}
		if n.VLANEnabled && n.VLAN.Set {
			v := n.VLAN.Val
			hint.VLAN = &v
		}
		subjectType := observation.SubjectIPv4
		if gwIP.To4() == nil {
			subjectType = observation.SubjectIPv6
		}
		// Subject is the network address; value carries the structured hint.
		out = append(out, emit{subjectType, ipnet.IP.String(), observation.AttrSubnetHint, hint.MarshalValue(), confSubnet})
	}
	return out
}

// deviceClass maps a UniFi device type to a coarse class. Model-level naming is
// left to the active prober's UBNT discovery (M4), which has richer model data.
func deviceClass(typ string) string {
	switch strings.ToLower(typ) {
	case "usw":
		return "UniFi Switch"
	case "uap":
		return "UniFi Access Point"
	case "ugw", "udm", "uxg":
		return "UniFi Gateway"
	case "":
		return ""
	default:
		return "UniFi Device"
	}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if s := strings.TrimSpace(v); s != "" {
			return s
		}
	}
	return ""
}

// decodeData unmarshals the data array of a private-API envelope into dst.
func decodeData(body []byte, dst any) error {
	var env envelope
	if err := json.Unmarshal(body, &env); err != nil {
		return fmt.Errorf("unifi: decode envelope: %w", err)
	}
	if len(env.Data) == 0 {
		return nil
	}
	if err := json.Unmarshal(env.Data, dst); err != nil {
		return fmt.Errorf("unifi: decode data: %w", err)
	}
	return nil
}
