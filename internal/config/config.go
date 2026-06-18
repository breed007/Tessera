// Package config loads Tessera's configuration from a YAML file plus
// environment overrides. The one hard rule: secrets (UniFi credential,
// Fingerbank key, SNMP community) come ONLY from the environment — they are
// never read from the file, never written back, and never logged (§5, §10).
package config

import "time"

// Config mirrors the §5 configuration block. Secret fields are unexported-by-
// convention (loaded from env into the Secrets struct), keeping them out of any
// struct that might get marshaled or logged.
type Config struct {
	Sensor      Sensor      `yaml:"sensor"`
	ActiveProbe ActiveProbe `yaml:"active_probe"`
	Discovery   Discovery   `yaml:"discovery"`
	UniFi       UniFi       `yaml:"unifi"`
	Fingerbank  Fingerbank  `yaml:"fingerbank"`
	Reconcile   Reconcile   `yaml:"reconcile"`
	Storage     Storage     `yaml:"storage"`
	API         API         `yaml:"api"`
	Alerts      Alerts      `yaml:"alerts"`

	// Secrets is populated from the environment, never from the YAML file.
	Secrets Secrets `yaml:"-"`
}

// API configures the read/annotation HTTP server (§M6/§M8). The inventory is
// sensitive network topology and the annotation endpoints write. It binds
// localhost by default; to expose it on the LAN, set an auth token
// (TESSERA_API_TOKEN). Binding a non-loopback address without a token is
// refused unless AllowInsecure is set (§M8 hardening).
type API struct {
	Enabled       bool   `yaml:"enabled"`
	ListenAddr    string `yaml:"listen_addr"`
	AuthUser      string `yaml:"auth_user"`      // bootstrap admin username; password hash from env
	AllowInsecure bool   `yaml:"allow_insecure"` // permit non-loopback bind with no auth (NOT recommended)
	TLS           bool   `yaml:"tls"`            // serve HTTPS (self-signed if no cert/key given) (§M10)
	TLSCertFile   string `yaml:"tls_cert_file"`  // optional: your own cert
	TLSKeyFile    string `yaml:"tls_key_file"`
	// RequireSetupToken gates first-run setup behind a one-time token (printed to
	// the log / a root-only file). Default false: first-run is open and the first
	// person to reach the UI becomes the admin (homelab norm). Enable it when
	// exposing an unconfigured instance to an untrusted network (§M11).
	RequireSetupToken bool `yaml:"require_setup_token"`
}

// Sensor configures the passive capture sources (§4.1). Enabled is the master
// switch for ALL passive traffic inspection: when false, no packets are captured
// on any source (the active prober and UniFi poller are unaffected — they don't
// sniff). Default off — capture is the most invasive capability and is opt-in.
type Sensor struct {
	Enabled        bool            `yaml:"enabled"`
	Sources        []CaptureSource `yaml:"sources"`
	DedupeWindowMS int             `yaml:"dedupe_window_ms"`
}

// CaptureSource is one capture vantage point — a normal interface (own broadcast
// domain) or a SPAN/mirror/TAP destination (cross-VLAN visibility) (§4.1).
type CaptureSource struct {
	Kind string `yaml:"kind"` // "interface" | "span"
	NIC  string `yaml:"nic"`
	BPF  string `yaml:"bpf"` // kernel capture filter; empty = Tessera's default set
}

// ActiveProbe configures the scoped, rate-limited prober (§4.2).
type ActiveProbe struct {
	Enabled   bool      `yaml:"enabled"`
	Subnets   []string  `yaml:"subnets"`   // MUST be explicit; never unscoped
	Interface string    `yaml:"interface"` // egress interface; empty → server's default-route interface
	ICMP      bool      `yaml:"icmp"`
	TCPPorts  []int     `yaml:"tcp_ports"`
	UDPPorts  []int     `yaml:"udp_ports"` // scanned only when listed (no default UDP sweep)
	// SNMPCommunities are tried in order against each host (first that answers
	// wins). Unlike the legacy single community (Secrets.SNMPCommunity, env-only),
	// these are visible, editable, and multi-valued — SNMP community strings are
	// low-sensitivity and operators want to see/manage them.
	SNMPCommunities []string  `yaml:"snmp_communities"`
	Rate            ProbeRate `yaml:"rate"`
}

type ProbeRate struct {
	MaxProbesPerSec int           `yaml:"max_probes_per_sec"`
	CycleInterval   time.Duration `yaml:"cycle_interval"`
}

// Discovery toggles the individual discovery techniques (the per-protocol
// scanning capabilities), independent of the master Sensor/ActiveProbe switches.
// Every technique is ON by default; operators de-select what they don't want.
// Passive_* techniques only do anything when sensor.enabled is true; active_* and
// tcp_behavioral/thorough_wake only when active_probe.enabled is true. All fields
// are pointers so an absent key keeps the all-on default (a present `false`
// disables); see ResolveDiscovery for the effective booleans.
type Discovery struct {
	// Passive (capture) parsers.
	PassiveARP     *bool `yaml:"passive_arp"`     // ARP + IPv6 NDP — ground-truth L2 bindings
	PassiveDHCP    *bool `yaml:"passive_dhcp"`    // DHCPv4/v6 — hostnames, fingerprints, leases
	PassiveMDNS    *bool `yaml:"passive_mdns"`    // mDNS / Bonjour — hostnames, services
	PassiveSSDP    *bool `yaml:"passive_ssdp"`    // SSDP / UPnP — device class, OS hints
	PassiveNetBIOS *bool `yaml:"passive_netbios"` // NetBIOS-NS — Windows names

	// Active (prober) techniques.
	ActiveICMP       *bool `yaml:"active_icmp"`        // ICMP echo liveness
	ActiveTCP        *bool `yaml:"active_tcp"`         // TCP-connect port scan + liveness
	ActiveUDP        *bool `yaml:"active_udp"`         // UDP service scan of the listed udp_ports
	ActiveBanners    *bool `yaml:"active_banners"`     // grab service banners on open ports
	ActiveReverseDNS *bool `yaml:"active_reverse_dns"` // PTR lookups for live hosts
	ActiveARPTable   *bool `yaml:"active_arp_table"`   // harvest the kernel ARP cache
	ActiveSNMP       *bool `yaml:"active_snmp"`        // SNMP sysName/sysDescr (needs a community)
	TCPBehavioral    *bool `yaml:"tcp_behavioral"`     // closed-port timing → OS/firewall behaviour (weak, corroborating)
	ThoroughWake     *bool `yaml:"thorough_wake"`      // extra wake pass for power-saving devices (slower)
}

// EffectiveDiscovery is Discovery with every toggle resolved to a concrete bool.
type EffectiveDiscovery struct {
	PassiveARP, PassiveDHCP, PassiveMDNS, PassiveSSDP, PassiveNetBIOS                 bool
	ActiveICMP, ActiveTCP, ActiveUDP, ActiveBanners, ActiveReverseDNS, ActiveARPTable bool
	ActiveSNMP, TCPBehavioral, ThoroughWake                                           bool
}

// Resolve turns the pointer-valued toggles into concrete booleans, defaulting
// every unset technique to ON.
func (d Discovery) Resolve() EffectiveDiscovery {
	on := func(p *bool) bool { return p == nil || *p }
	return EffectiveDiscovery{
		PassiveARP: on(d.PassiveARP), PassiveDHCP: on(d.PassiveDHCP), PassiveMDNS: on(d.PassiveMDNS),
		PassiveSSDP: on(d.PassiveSSDP), PassiveNetBIOS: on(d.PassiveNetBIOS),
		ActiveICMP: on(d.ActiveICMP), ActiveTCP: on(d.ActiveTCP), ActiveUDP: on(d.ActiveUDP),
		ActiveBanners:    on(d.ActiveBanners),
		ActiveReverseDNS: on(d.ActiveReverseDNS), ActiveARPTable: on(d.ActiveARPTable),
		ActiveSNMP: on(d.ActiveSNMP), TCPBehavioral: on(d.TCPBehavioral), ThoroughWake: on(d.ThoroughWake),
	}
}

// UniFi configures the read-only controller poller (§4.3). Credentials arrive
// via env (Secrets), not here.
type UniFi struct {
	Enabled      bool          `yaml:"enabled"`
	BaseURL      string        `yaml:"base_url"`
	PathPrefix   string        `yaml:"path_prefix"` // "/proxy/network" (UniFi OS), "" (8443 software), etc.
	Site         string        `yaml:"site"`        // controller site name (default "default")
	VerifyTLS    bool          `yaml:"verify_tls"`  // self-signed controllers: false
	PollInterval time.Duration `yaml:"poll_interval"`
}

// Fingerbank configures device-classification enrichment (§7). Disabled by
// default for privacy.
type Fingerbank struct {
	Enabled       bool           `yaml:"enabled"`
	Mode          string         `yaml:"mode"` // api | local_db | off
	Rate          FingerbankRate `yaml:"rate"`
	CacheTTL      time.Duration  `yaml:"cache_ttl"`
	SubmitUnknown bool           `yaml:"submit_unknown"`
	DBPath        string         `yaml:"db_path"` // local_db mode: path to the offline Fingerbank SQLite
}

type FingerbankRate struct {
	MaxPerHour int `yaml:"max_per_hour"` // stay UNDER the 300/hr free ceiling
	Burst      int `yaml:"burst"`
}

// Reconcile configures aging and decay thresholds (§3.3) plus log compaction.
type Reconcile struct {
	StaleAfter         time.Duration `yaml:"stale_after"`
	FreeAfter          time.Duration `yaml:"free_after"`
	ConfidenceHalfLife time.Duration `yaml:"confidence_half_life"`
	CompactInterval    time.Duration `yaml:"compact_interval"` // collapse repeated log rows this often; 0 = never (§M9)
}

// Storage configures the persistence driver (§5).
type Storage struct {
	Driver string `yaml:"driver"` // sqlite (postgres swappable later)
	DSN    string `yaml:"dsn"`
}

// Secrets holds values that must never touch the config file or logs (§5).
type Secrets struct {
	UniFiUsername   string
	UniFiPassword   string
	UniFiAPIKey     string
	FingerbankKey   string
	SNMPCommunity   string
	APIToken        string // optional bearer token for the HTTP API (§M8)
	APIPasswordHash string // bcrypt hash of the bootstrap admin password (§M9)
	SecretKey       string // master key for encrypting settings secrets at rest (§M10)
	AlertWebhookURL string // destination URL for alert notifications (may carry a token)
}

// Alerts configures proactive notifications dispatched on reconciliation deltas.
// The destination URL is a secret (Secrets.AlertWebhookURL); everything else is
// plain config.
type Alerts struct {
	Enabled   bool   `yaml:"enabled"`
	Kind      string `yaml:"kind"` // webhook | slack | discord | ntfy
	NewDevice    bool `yaml:"new_device"`
	Offline      bool `yaml:"offline"`
	Online       bool `yaml:"online"`
	IPChanged    bool `yaml:"ip_changed"`
	Conflict     bool `yaml:"conflict"`
	RiskyService bool `yaml:"risky_service"`
}

// Default returns a Config populated with the §5 defaults, before file/env
// overlay.
func Default() Config {
	return Config{
		Sensor: Sensor{DedupeWindowMS: 50},
		ActiveProbe: ActiveProbe{
			Rate: ProbeRate{MaxProbesPerSec: 20, CycleInterval: 15 * time.Minute},
		},
		UniFi: UniFi{
			PathPrefix:   "/proxy/network",
			Site:         "default",
			VerifyTLS:    false,
			PollInterval: 5 * time.Minute,
		},
		Fingerbank: Fingerbank{
			Enabled:       false, // privacy: off by default (§7)
			Mode:          "api",
			Rate:          FingerbankRate{MaxPerHour: 250, Burst: 10},
			CacheTTL:      720 * time.Hour,
			SubmitUnknown: false,
		},
		Reconcile: Reconcile{
			StaleAfter:         24 * time.Hour,
			FreeAfter:          168 * time.Hour,
			ConfidenceHalfLife: 72 * time.Hour,
			CompactInterval:    6 * time.Hour,
		},
		Storage: Storage{
			Driver: "sqlite",
			DSN:    "/var/lib/tessera/tessera.db",
		},
		API: API{
			Enabled: true,
			// 10404: deliberately uncommon (avoids NetBox 8000/8080, phpIPAM 80,
			// and the usual homelab ports); >1024, <32768 (below the ephemeral
			// range). Binds all interfaces so it's reachable on the LAN out of the
			// box; set 127.0.0.1:10404 for localhost-only.
			ListenAddr: "0.0.0.0:10404",
		},
	}
}
