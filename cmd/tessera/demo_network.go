package main

import (
	"context"
	"fmt"
	"time"

	"github.com/breed007/Tessera/internal/observation"
)

// A larger synthetic network for `tessera demo -full`.
//
// The default demo seeds eleven observations: enough to show the pipeline, far
// too few to show what the inventory actually looks like. This one populates a
// plausible small network so an evaluator can open the UI and see the thing
// working — device classes, OS versions, subnets, services, topology and a real
// disagreement — without pointing Tessera at anything they own.
//
// EVERY VALUE HERE IS INVENTED. The addresses are RFC 5737/1918 documentation
// ranges, the MACs are drawn from the reserved aa:bb:cc prefix (with a few
// vendor-shaped ones where the OUI is the point), and no hostname, room or
// person corresponds to anybody. That is deliberate: a screenshot of a real
// network is a floor plan of somebody's house, and this file exists so nobody
// has to publish one.
//
// It also doubles as a fixture for the identification work: the Windows,
// macOS, tvOS, Proxmox and Debian entries carry exactly the os_version shapes
// the probes in internal/collector/active produce, so the UI's composition of
// "os_guess + os_version" is exercised against real output shapes.

// demoDevice is one synthetic host and everything known about it.
type demoDevice struct {
	mac       string
	ip        string
	vendor    string
	hostname  string
	class     string
	os        string
	osVersion string // bare, as the collectors emit it
	model     string
	firmware  string
	ports     []string // "tcp/443"
	switchIfc int      // port number on the core switch; 0 = not wired
}

// The network: a small home lab across three subnets.
var demoNetwork = []demoDevice{
	// ── infrastructure ──────────────────────────────────────────────────────
	{mac: "aa:bb:cc:10:00:01", ip: "10.10.0.1", vendor: "Ubiquiti Inc.", hostname: "gateway",
		class: "router / gateway", os: "UniFi OS", osVersion: "4.1.9", model: "UDM Pro",
		firmware: "4.1.9", ports: []string{"tcp/443", "tcp/22"}},
	{mac: "aa:bb:cc:10:00:02", ip: "10.10.0.2", vendor: "Ubiquiti Inc.", hostname: "core-switch",
		class: "switch", model: "USW Pro 24 PoE", firmware: "7.0.50", ports: []string{"tcp/22"}},
	{mac: "aa:bb:cc:10:00:03", ip: "10.10.0.3", vendor: "Ubiquiti Inc.", hostname: "ap-study",
		class: "access point", model: "U7 Pro", firmware: "7.0.92", switchIfc: 2},

	// ── servers ─────────────────────────────────────────────────────────────
	{mac: "aa:bb:cc:10:00:10", ip: "10.10.0.10", vendor: "Intel Corporate", hostname: "pve1",
		class: "server", os: "Proxmox VE", osVersion: "9.2.5",
		ports: []string{"tcp/22", "tcp/8006"}, switchIfc: 5},
	{mac: "aa:bb:cc:10:00:11", ip: "10.10.0.11", vendor: "Synology Incorporated", hostname: "nas01",
		class: "NAS", os: "Linux", model: "DS923+",
		ports: []string{"tcp/22", "tcp/443", "tcp/5000", "tcp/2049"}, switchIfc: 6},
	{mac: "aa:bb:cc:10:00:12", ip: "10.10.0.12", vendor: "Intel Corporate", hostname: "buildbox",
		class: "server", os: "Debian Linux", osVersion: "13",
		ports: []string{"tcp/22", "tcp/80"}, switchIfc: 7},

	// ── virtual guests (the hypervisor's own inventory) ─────────────────────
	{mac: "aa:bb:cc:10:00:20", ip: "10.10.0.20", vendor: "Proxmox Server Solutions GmbH",
		hostname: "plex", class: "Container", os: "Debian Linux", osVersion: "13",
		ports: []string{"tcp/32400"}},
	{mac: "aa:bb:cc:10:00:21", ip: "10.10.0.21", vendor: "Proxmox Server Solutions GmbH",
		hostname: "adguard", class: "Container", os: "Debian Linux", osVersion: "13",
		ports: []string{"tcp/80", "tcp/443"}},
	{mac: "aa:bb:cc:10:00:22", ip: "10.10.0.22", vendor: "Proxmox Server Solutions GmbH",
		hostname: "docs", class: "Virtual Machine", os: "Ubuntu Linux", osVersion: "24.04",
		ports: []string{"tcp/22", "tcp/80"}},

	// ── workstations — the identification work's headline cases ─────────────
	{mac: "aa:bb:cc:10:00:30", ip: "10.10.0.30", vendor: "Dell Inc.", hostname: "workstation01",
		class: "computer", os: "Windows", osVersion: "11 24H2 (build 26100)",
		ports: []string{"tcp/445", "tcp/3389"}, switchIfc: 9},
	{mac: "aa:bb:cc:10:00:31", ip: "10.10.0.31", vendor: "Apple, Inc.", hostname: "studio",
		class: "computer", os: "macOS", osVersion: "26.6", model: "Mac Studio (2025, M4 Max)",
		ports: []string{"tcp/22", "tcp/7000"}},
	{mac: "aa:bb:cc:10:00:32", ip: "10.10.0.32", vendor: "LENOVO", hostname: "thinkpad",
		class: "computer", os: "Ubuntu Linux", osVersion: "24.04", ports: []string{"tcp/22"}},

	// ── printer ─────────────────────────────────────────────────────────────
	{mac: "aa:bb:cc:10:00:40", ip: "10.10.0.40", vendor: "Brother Industries, LTD.",
		hostname: "printer", class: "printer", model: "HL-L2400DW",
		ports: []string{"tcp/631", "tcp/9100"}, switchIfc: 12},

	// ── media ───────────────────────────────────────────────────────────────
	{mac: "aa:bb:cc:20:00:01", ip: "10.10.20.11", vendor: "Apple, Inc.", hostname: "appletv-lounge",
		class: "media / TV device", os: "tvOS", osVersion: "26.6", model: "Apple TV 4K (3rd generation)"},
	{mac: "aa:bb:cc:20:00:02", ip: "10.10.20.12", vendor: "Google, Inc.", hostname: "chromecast",
		class: "media / TV device", model: "Chromecast Ultra"},
	{mac: "aa:bb:cc:20:00:03", ip: "10.10.20.13", vendor: "Sonos, Inc.", hostname: "sonos-kitchen",
		class: "speaker", model: "Sonos One"},
	{mac: "aa:bb:cc:20:00:04", ip: "10.10.20.14", vendor: "Amazon Technologies Inc.",
		hostname: "echo-study", class: "speaker"},

	// ── cameras and IoT ─────────────────────────────────────────────────────
	{mac: "aa:bb:cc:20:00:10", ip: "10.10.20.21", vendor: "Reolink", hostname: "camera-front",
		class: "camera", ports: []string{"tcp/554", "tcp/80"}},
	{mac: "aa:bb:cc:20:00:11", ip: "10.10.20.22", vendor: "Reolink", hostname: "camera-side",
		class: "camera", ports: []string{"tcp/554", "tcp/80"}},
	{mac: "aa:bb:cc:20:00:20", ip: "10.10.20.31", vendor: "Espressif Inc.", hostname: "esp32-node-01",
		class: "garage door controller", os: "ESPHome", ports: []string{"tcp/80"}},
	{mac: "aa:bb:cc:20:00:21", ip: "10.10.20.32", vendor: "Espressif Inc.", hostname: "esp32-node-02",
		class: "IoT device", os: "ESPHome", ports: []string{"tcp/80"}},
	{mac: "aa:bb:cc:20:00:30", ip: "10.10.20.41", vendor: "Signify Netherlands B.V.",
		hostname: "hue-bridge", class: "IoT device", ports: []string{"tcp/80", "tcp/443"}},
	{mac: "aa:bb:cc:20:00:31", ip: "10.10.20.42", vendor: "ecobee Inc.", hostname: "thermostat",
		class: "thermostat"},

	// ── mobile — locally-administered MACs, flagged as randomized (§6) ──────
	{mac: "b2:bb:cc:30:00:01", ip: "10.10.30.11", hostname: "phone", class: "Apple mobile device",
		os: "iOS", osVersion: "26.1", ports: []string{"tcp/62078"}},
	{mac: "b2:bb:cc:30:00:02", ip: "10.10.30.12", hostname: "tablet", class: "Apple mobile device",
		os: "iPadOS", osVersion: "26.1"},
}

// demoSubnets are the three networks the devices above sit in.
var demoSubnets = []observation.SubnetHintValue{
	{CIDR: "10.10.0.0/24", Name: "LAN", Gateway: "10.10.0.1", VLAN: intPtr(1)},
	{CIDR: "10.10.20.0/24", Name: "IoT", Gateway: "10.10.20.1", VLAN: intPtr(20)},
	{CIDR: "10.10.30.0/24", Name: "Guest", Gateway: "10.10.30.1", VLAN: intPtr(30)},
}

func intPtr(v int) *int { return &v }

// seedDemoNetwork writes the synthetic network through the ordinary Sink — the
// same write path a real collector uses, so nothing here is a special case the
// reconciler knows about.
//
// Sources are chosen to match where each fact would really come from: bindings
// and vendors from the passive sensor, classification and versions from the
// probes that produce them, models and topology from the controller. That is
// what makes the resulting "how was this identified" trail truthful rather than
// decorative.
func seedDemoNetwork(ctx context.Context, sink *observation.Sink, t0 time.Time) error {
	at := func(n int) observation.Opt {
		return observation.At(t0.Add(time.Duration(n) * time.Second))
	}
	n := 0
	rec := func(src observation.Source, st observation.SubjectType, subj string,
		attr observation.Attribute, val string, conf int) error {
		n++
		_, err := sink.Record(ctx, src, st, subj, attr, val, conf, at(n))
		return err
	}

	for _, s := range demoSubnets {
		if err := rec(observation.SourceUniFi, observation.SubjectIPv4, network(s.CIDR),
			observation.AttrSubnetHint, s.MarshalValue(), 95); err != nil {
			return err
		}
	}

	for _, d := range demoNetwork {
		if err := rec(observation.SourcePassiveARP, observation.SubjectMAC, d.mac,
			observation.AttrIPBinding, d.ip, 95); err != nil {
			return err
		}
		if d.vendor != "" {
			if err := rec(observation.SourcePassiveARP, observation.SubjectMAC, d.mac,
				observation.AttrOUIVendor, d.vendor, 90); err != nil {
				return err
			}
		}
		if d.hostname != "" {
			if err := rec(observation.SourcePassiveDHCP, observation.SubjectMAC, d.mac,
				observation.AttrHostname, d.hostname, 80); err != nil {
				return err
			}
		}
		if d.class != "" {
			if err := rec(observation.SourceActiveMDNS, observation.SubjectMAC, d.mac,
				observation.AttrDeviceClass, d.class, 78); err != nil {
				return err
			}
		}
		// OS and version travel together from one source, which is what lets the
		// reconciler attach the version to the name (see engine.sourceAsserted).
		if d.os != "" {
			src := osSource(d.os)
			if err := rec(src, observation.SubjectMAC, d.mac,
				observation.AttrOSGuess, d.os, 86); err != nil {
				return err
			}
			if d.osVersion != "" {
				if err := rec(src, observation.SubjectMAC, d.mac,
					observation.AttrOSVersion, d.osVersion, 88); err != nil {
					return err
				}
			}
		}
		if d.model != "" {
			if err := rec(observation.SourceActiveMDNS, observation.SubjectMAC, d.mac,
				observation.AttrModel, d.model, 88); err != nil {
				return err
			}
		}
		if d.firmware != "" {
			if err := rec(observation.SourceUniFi, observation.SubjectMAC, d.mac,
				observation.AttrFirmware, d.firmware, 90); err != nil {
				return err
			}
		}
		for _, p := range d.ports {
			if err := rec(observation.SourceActiveTCP, observation.SubjectIPv4, d.ip,
				observation.AttrOpenPort, p, 85); err != nil {
				return err
			}
		}
		if d.switchIfc > 0 {
			if err := rec(observation.SourceUniFi, observation.SubjectMAC, d.mac,
				observation.AttrSwitchPort,
				fmt.Sprintf("aa:bb:cc:10:00:02/%d", d.switchIfc), 95); err != nil {
				return err
			}
		}
		if err := rec(observation.SourceActiveICMP, observation.SubjectIPv4, d.ip,
			observation.AttrLiveness, "up", 90); err != nil {
			return err
		}
	}

	// One genuine disagreement, so the conflicts view has something real in it:
	// a vendor fingerprint calls the Synology a computer, its own mDNS says NAS.
	// The higher-confidence value stays current and the disagreement is surfaced
	// rather than hidden (§3.3).
	return rec(observation.SourceFingerbank, observation.SubjectMAC, "aa:bb:cc:10:00:11",
		observation.AttrDeviceClass, "computer", 62)
}

// osSource maps a synthetic OS string back to the probe that would really have
// produced it, so the demo's evidence trail matches the code's behaviour.
func osSource(os string) observation.Source {
	switch os {
	case "Windows":
		return observation.SourceActiveNTLM
	case "Proxmox VE":
		return observation.SourceActiveProxmoxVE
	case "ESPHome":
		return observation.SourceActiveESPHome
	case "Debian Linux", "Ubuntu Linux":
		return observation.SourceActiveTCP // the SSH banner
	case "macOS", "tvOS", "iOS", "iPadOS":
		return observation.SourceActiveMedia
	}
	return observation.SourceActiveMDNS
}

// network strips a CIDR to its network address, which is the subject an
// AttrSubnetHint observation is keyed on.
func network(cidr string) string {
	for i := 0; i < len(cidr); i++ {
		if cidr[i] == '/' {
			return cidr[:i]
		}
	}
	return cidr
}
