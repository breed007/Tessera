package reconcile

import (
	"sort"
	"strings"
)

// Generic inference (ported in spirit from IP Recon's GenericInference): a
// last-pass layer that derives a Hardware/Device class and Operating System for
// hosts the high-confidence collectors (UniFi, SNMP, SSDP, Fingerbank) left
// unclassified. It combines several weak-but-cheap signals — open ports, service
// banners, OUI vendor, hostname, DHCP vendor-class (option 60), and the TCP
// behavioural fingerprint — and votes.
//
// Confidence follows §6 (honest confidence with provenance): it scales with how
// many INDEPENDENT signal categories agree, not with raw vote weight. One lone
// signal stays low; three independent signals that agree are genuinely
// trustworthy and may reach the high band. This is safe because inference only
// ever fills a gap — it runs solely when an authoritative collector left the
// attribute empty (see engine.snapshot) — so a real classification is never
// overridden regardless of the number we attach here.

// inferInput is everything the inference layer looks at for one host.
type inferInput struct {
	openPorts   []int
	banners     []string
	vendor      string
	hostname    string
	dhcpVendor  string // DHCP option 60 vendor-class id, e.g. "android-dhcp-13", "MSFT 5.0"
	tcpBehavior string // rst_immediate | silent_drop | icmp_unreachable
}

// inferResult is the derived classification. A confidence of 0 means "no signal".
type inferResult struct {
	deviceClass string
	osGuess     string
	deviceConf  int
	osConf      int
}

// signal categories — confidence scales with how many DISTINCT categories agree.
const (
	catPort       = "port"
	catVendor     = "vendor"
	catHostname   = "hostname"
	catBanner     = "banner"
	catDHCPVendor = "dhcp_vendor"
	catTCP        = "tcp"
)

// tally accumulates the votes for one candidate value plus the set of distinct
// signal categories that contributed — the provenance that drives confidence.
type tally struct {
	weight int
	cats   map[string]bool
}

// voter collects weighted, provenance-tagged votes for a set of candidates.
type voter map[string]*tally

func (v voter) add(candidate, category string, weight int) {
	if candidate == "" {
		return
	}
	t := v[candidate]
	if t == nil {
		t = &tally{cats: map[string]bool{}}
		v[candidate] = t
	}
	t.weight += weight
	t.cats[category] = true
}

// winner returns the highest-weighted candidate (deterministic tie-break by
// name) and its confidence, derived from the count of distinct categories.
func (v voter) winner() (string, int) {
	keys := make([]string, 0, len(v))
	for k := range v {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	best, bestW := "", 0
	for _, k := range keys {
		if v[k].weight > bestW {
			best, bestW = k, v[k].weight
		}
	}
	if best == "" {
		return "", 0
	}
	return best, voteConfidence(len(v[best].cats), v[best].weight)
}

// inferIdentity votes a device class and OS from the available weak signals.
func inferIdentity(in inferInput) inferResult {
	dev := voter{}
	os := voter{}

	// ── open ports ──────────────────────────────────────────────────────────
	portset := map[int]bool{}
	for _, p := range in.openPorts {
		portset[p] = true
	}
	has := func(ps ...int) bool {
		for _, p := range ps {
			if portset[p] {
				return true
			}
		}
		return false
	}
	if has(9100, 515, 631) {
		dev.add("printer", catPort, 2)
	}
	if has(554, 8554, 37777) {
		dev.add("camera", catPort, 1)
	}
	if has(32400) {
		dev.add("media server", catPort, 2)
	}
	if has(445, 139) {
		os.add("Windows", catPort, 2)
		dev.add("computer", catPort, 1)
	}
	if has(3389) {
		os.add("Windows", catPort, 2)
	}
	if has(22) {
		os.add("Linux / Unix", catPort, 1)
		dev.add("computer", catPort, 1)
	}
	if has(62078) {
		dev.add("Apple mobile device", catPort, 2)
		os.add("iOS", catPort, 2)
	}
	if has(1883, 8883, 5683) {
		dev.add("IoT device", catPort, 1)
	}
	if has(2049, 111, 5000, 5001) {
		dev.add("NAS", catPort, 1)
	}
	if has(5060, 5061) {
		dev.add("VoIP device", catPort, 1)
	}
	if has(53) && has(80, 443) {
		dev.add("router / gateway", catPort, 1)
	}

	// ── OUI vendor ──────────────────────────────────────────────────────────
	v := strings.ToLower(in.vendor)
	h := normalizeHost(in.hostname)
	switch {
	case containsAny(v, "ubiquiti", "unifi"):
		dev.add("network gear", catVendor, 2)
	case containsAny(v, "raspberry"):
		dev.add("single-board computer", catVendor, 2)
		os.add("Linux", catVendor, 2)
	case containsAny(v, "apple"):
		// Apple OUI alone is a weak OS hint; the family resolver below sharpens it
		// into a device class when the hostname/services give a model cue.
		applyAppleFamily(dev, os, h, catVendor)
	case containsAny(v, "espressif", "tuya", "shelly", "sonoff", "tasmota"):
		dev.add("IoT device", catVendor, 2)
	case containsAny(v, "ring", "amcrest", "hikvision", "dahua", "axis comm", "reolink", "wyze", "eufy", "ezviz", "lorex", "nest labs", "google nest"):
		dev.add("camera", catVendor, 2)
	case containsAny(v, "sonos"):
		dev.add("speaker", catVendor, 2)
	case containsAny(v, "synology", "qnap"):
		dev.add("NAS", catVendor, 2)
	case containsAny(v, "roku", "nvidia", "tcl", "vizio"):
		dev.add("media / TV device", catVendor, 2)
	case containsAny(v, "amazon"):
		dev.add("media / TV device", catVendor, 1) // Fire TV / Echo — ambiguous, weak
	case containsAny(v, "google"):
		dev.add("media / TV device", catVendor, 1) // Chromecast / Home — ambiguous, weak
	case containsAny(v, "hewlett", "epson", "canon", "brother", "lexmark"):
		dev.add("printer", catVendor, 2)
	case containsAny(v, "signify", "philips", "wiz", "lifx", "texas instruments"):
		dev.add("IoT device", catVendor, 1)
	case containsAny(v, "dell", "lenovo", "asustek", "gigabyte", "micro-star", "intel corp"):
		dev.add("computer", catVendor, 1)
	}

	// ── hostname ────────────────────────────────────────────────────────────
	// Matched against a separator-stripped form (joined) for product names, plus
	// the token list for short, ambiguous tokens — so "Apple TV 4K", "Ring
	// Floodlight", "esp32-node-01" and "studiombp14" all resolve.
	switch {
	case h.joinedHas("iphone", "ipad", "ipod"):
		dev.add("Apple mobile device", catHostname, 2)
		os.add("iOS", catHostname, 2)
	case h.joinedHas("appletv", "homepod", "macbook", "mbp", "imac", "macmini", "macpro"):
		applyAppleFamily(dev, os, h, catHostname)
	case h.joinedHas("android", "galaxy", "pixel", "oneplus"):
		dev.add("mobile phone", catHostname, 2)
		os.add("Android", catHostname, 2)
	case h.joinedHas("desktop", "win") || h.hasTok("pc"):
		os.add("Windows", catHostname, 1)
		dev.add("computer", catHostname, 1)
	case h.joinedHas("printer", "laserjet", "officejet", "envy"):
		dev.add("printer", catHostname, 1)
	case h.joinedHas("camera", "doorbell", "floodlight", "ring", "nestcam", "wyze"):
		dev.add("camera", catHostname, 1)
	case h.joinedHas("roku", "firetv", "chromecast", "shield") || h.hasTok("tv"):
		dev.add("media / TV device", catHostname, 1)
	case h.joinedHas("synology", "qnap", "truenas", "nas"):
		dev.add("NAS", catHostname, 1)
	case h.joinedHas("raspberry", "raspberrypi", "rpi"):
		dev.add("single-board computer", catHostname, 1)
		os.add("Linux", catHostname, 1)
	case h.joinedHas("esp32", "esp8266", "espressif", "shelly", "sonoff", "tasmota"):
		dev.add("IoT device", catHostname, 2)
	}

	// ── DHCP vendor-class (option 60) ─────────────────────────────────────────
	// Plain-text and highly diagnostic; the strongest offline signal after a
	// first-party fingerprint. (Option 55, the parameter-request list, is best
	// matched by the Fingerbank local DB, which is keyed on it.)
	classifyDHCPVendor(dev, os, in.dhcpVendor)

	// ── service banners ─────────────────────────────────────────────────────
	for _, b := range in.banners {
		lb := strings.ToLower(b)
		switch {
		case containsAny(lb, "ubuntu", "debian", "raspbian"):
			os.add("Linux", catBanner, 1)
		case containsAny(lb, "microsoft", "iis", "win64", "win32"):
			os.add("Windows", catBanner, 1)
		case containsAny(lb, "openwrt"):
			os.add("Linux (OpenWrt)", catBanner, 1)
			dev.add("router / gateway", catBanner, 1)
		case containsAny(lb, "mikrotik", "routeros"):
			dev.add("router / gateway", catBanner, 1)
		case containsAny(lb, "darwin"):
			os.add("macOS", catBanner, 1)
		}
	}

	// ── TCP behavioural fingerprint (genuinely weak; corroboration only) ─────
	switch in.tcpBehavior {
	case "silent_drop":
		dev.add("firewalled / embedded device", catTCP, 1)
	case "rst_immediate":
		// A general-purpose OS with no host firewall — only nudge an OS guess we
		// already have some other reason to believe.
		if len(os) > 0 {
			keys := make([]string, 0, len(os))
			for k := range os {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			os.add(keys[0], catTCP, 1)
		}
	}

	var res inferResult
	if c, conf := dev.winner(); c != "" {
		res.deviceClass, res.deviceConf = c, conf
	}
	if c, conf := os.winner(); c != "" {
		res.osGuess, res.osConf = c, conf
	}
	return res
}

// applyAppleFamily turns an Apple cue (vendor or hostname) into the most specific
// device class + OS the hostname supports, defaulting to a Mac. cat names the
// signal category so multi-signal agreement is counted honestly.
func applyAppleFamily(dev, os voter, h hostName, cat string) {
	switch {
	case h.joinedHas("appletv"):
		dev.add("media / TV device", cat, 2)
		os.add("tvOS", cat, 2)
	case h.joinedHas("homepod"):
		dev.add("speaker", cat, 2)
	case h.joinedHas("iphone", "ipad", "ipod"):
		dev.add("Apple mobile device", cat, 2)
		os.add("iOS", cat, 2)
	case h.joinedHas("macbook", "mbp", "imac", "macmini", "macpro") || h.hasTok("mac"):
		dev.add("computer", cat, 2)
		os.add("macOS", cat, 2)
	default:
		// Apple OUI with no model cue: weak OS hint only.
		os.add("macOS / iOS", cat, 1)
	}
}

// classifyDHCPVendor maps a DHCP option-60 vendor-class id to a class/OS. The
// strings are stable, plain-text, and device-defined.
func classifyDHCPVendor(dev, os voter, vendorClass string) {
	s := strings.ToLower(strings.TrimSpace(vendorClass))
	if s == "" {
		return
	}
	switch {
	case containsAny(s, "android"):
		dev.add("mobile phone", catDHCPVendor, 2)
		os.add("Android", catDHCPVendor, 2)
	case containsAny(s, "msft"):
		os.add("Windows", catDHCPVendor, 2)
		dev.add("computer", catDHCPVendor, 1)
	case containsAny(s, "dhcpcd"):
		os.add("Linux", catDHCPVendor, 1)
	case containsAny(s, "udhcp"):
		// BusyBox udhcp — overwhelmingly embedded Linux.
		os.add("Linux", catDHCPVendor, 1)
		dev.add("IoT device", catDHCPVendor, 1)
	case containsAny(s, "esp", "espressif"):
		dev.add("IoT device", catDHCPVendor, 2)
	case containsAny(s, "ring"):
		dev.add("camera", catDHCPVendor, 2)
	case containsAny(s, "roku"):
		dev.add("media / TV device", catDHCPVendor, 2)
	case containsAny(s, "amazon", "fireos", "fire os"):
		dev.add("media / TV device", catDHCPVendor, 1)
	case containsAny(s, "google", "chromecast"):
		dev.add("media / TV device", catDHCPVendor, 1)
	case containsAny(s, "hue", "philips"):
		dev.add("IoT device", catDHCPVendor, 2)
	case containsAny(s, "sonos"):
		dev.add("speaker", catDHCPVendor, 2)
	case containsAny(s, "ubnt", "ubiquiti"):
		dev.add("network gear", catDHCPVendor, 2)
	case containsAny(s, "hewlett", "hp "):
		dev.add("printer", catDHCPVendor, 1)
	}
}

// voteConfidence maps the count of distinct contributing signal categories (and,
// as a secondary nudge, the raw weight) to a confidence. Confidence scales with
// independent agreement (§6): a single category stays in the LOW/MEDIUM bands; a
// genuine multi-signal consensus may reach the HIGH band. Inference only fills
// gaps, so this never overrides an authoritative collector.
func voteConfidence(categories, weight int) int {
	switch {
	case categories >= 3:
		return 80 // three independent signals agree → high
	case categories == 2 && weight >= 4:
		return 72 // two strong independent signals agree → high
	case categories == 2:
		return 60 // two signals agree → medium-high
	case weight >= 2:
		return 45 // one weight-2 signal → medium
	default:
		return 30 // one weak signal → low
	}
}

// hostName is a hostname pre-split into a separator-stripped "joined" form (for
// matching multi-word product names like "Apple TV 4K") and a token list (for
// short, ambiguous tokens like "pc" or "mbp").
type hostName struct {
	joined string
	tokens map[string]bool
}

func normalizeHost(raw string) hostName {
	lower := strings.ToLower(raw)
	var b strings.Builder
	tokens := map[string]bool{}
	var cur strings.Builder
	flush := func() {
		if cur.Len() > 0 {
			tokens[cur.String()] = true
			cur.Reset()
		}
	}
	for _, r := range lower {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			cur.WriteRune(r)
		} else {
			flush()
		}
	}
	flush()
	return hostName{joined: b.String(), tokens: tokens}
}

func (h hostName) joinedHas(subs ...string) bool {
	for _, sub := range subs {
		if sub != "" && strings.Contains(h.joined, sub) {
			return true
		}
	}
	return false
}

func (h hostName) hasTok(toks ...string) bool {
	for _, t := range toks {
		if h.tokens[t] {
			return true
		}
	}
	return false
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
