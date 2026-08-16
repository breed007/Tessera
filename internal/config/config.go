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
	Proxmox     Proxmox     `yaml:"proxmox"`
	Fingerbank  Fingerbank  `yaml:"fingerbank"`
	DHCP        DHCP        `yaml:"dhcp"`
	DNS         DNS         `yaml:"dns"`
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
	Enabled   bool     `yaml:"enabled"`
	Subnets   []string `yaml:"subnets"`   // MUST be explicit; never unscoped
	Interface string   `yaml:"interface"` // egress interface; empty → server's default-route interface
	ICMP      bool     `yaml:"icmp"`
	TCPPorts  []int    `yaml:"tcp_ports"`
	UDPPorts  []int    `yaml:"udp_ports"` // scanned only when listed (no default UDP sweep)
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
	ActiveMDNS       *bool `yaml:"active_mdns"`        // unicast mDNS query → service types, model= (Fire TV, Apple TV, Cast, …)
	ActiveMedia      *bool `yaml:"active_media"`       // AirPlay/Cast HTTP identity probes (exact model + name)
	ActiveNTLM       *bool `yaml:"active_ntlm"`        // NTLMSSP challenge on SMB/RDP → Windows release + build
	ActiveProxmox    *bool `yaml:"active_proxmox"`     // unauthenticated Proxmox VE login page → identity + version
	ActiveESPHome    *bool `yaml:"active_esphome"`     // ESPHome /events → device title + entity set
	TCPBehavioral    *bool `yaml:"tcp_behavioral"`     // closed-port timing → OS/firewall behaviour (weak, corroborating)
	ThoroughWake     *bool `yaml:"thorough_wake"`      // extra wake pass for power-saving devices (slower)
}

// EffectiveDiscovery is Discovery with every toggle resolved to a concrete bool.
type EffectiveDiscovery struct {
	PassiveARP, PassiveDHCP, PassiveMDNS, PassiveSSDP, PassiveNetBIOS                 bool
	ActiveICMP, ActiveTCP, ActiveUDP, ActiveBanners, ActiveReverseDNS, ActiveARPTable bool
	ActiveSNMP, ActiveMDNS, ActiveMedia, TCPBehavioral, ThoroughWake                  bool
	ActiveNTLM, ActiveProxmox, ActiveESPHome                                          bool
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
		ActiveSNMP: on(d.ActiveSNMP), ActiveMDNS: on(d.ActiveMDNS), ActiveMedia: on(d.ActiveMedia),
		ActiveNTLM: on(d.ActiveNTLM), ActiveProxmox: on(d.ActiveProxmox), ActiveESPHome: on(d.ActiveESPHome),
		TCPBehavioral: on(d.TCPBehavioral), ThoroughWake: on(d.ThoroughWake),
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

	// Auto-prune: forget devices not seen on the network for ForgetDormantDays.
	// Off by default (destructive: deletes history + annotations).
	ForgetDormantEnabled bool `yaml:"forget_dormant_enabled"`
	ForgetDormantDays    int  `yaml:"forget_dormant_days"`
}

// MaxProxmoxInstances caps how many Proxmox VE endpoints can be polled at once.
const MaxProxmoxInstances = 5

// Proxmox configures the read-only Proxmox VE collector (VM/CT inventory). Up to
// MaxProxmoxInstances endpoints, each with its own URL and auth. Per-instance
// credentials are secrets (matched by index): token env TESSERA_PROXMOX_TOKEN and
// password env TESSERA_PROXMOX_PASSWORD seed instance 0. Off by default.
type Proxmox struct {
	Enabled      bool              `yaml:"enabled"`
	PollInterval time.Duration     `yaml:"poll_interval"`
	Instances    []ProxmoxInstance `yaml:"instances"`

	// Deprecated single-instance fields (pre-multi-instance configs). Migrated
	// into Instances[0] by Normalize; kept only for back-compat parsing.
	BaseURL   string `yaml:"base_url,omitempty"`
	VerifyTLS bool   `yaml:"verify_tls,omitempty"`
}

// ProxmoxInstance is one PVE endpoint. AuthMode selects how the matching secret
// (Secrets.ProxmoxTokens[i] / ProxmoxPasswords[i]) is used.
type ProxmoxInstance struct {
	Name      string `yaml:"name" json:"name"`             // display label (e.g. "pve-lab"); optional
	BaseURL   string `yaml:"base_url" json:"base_url"`     // https://proxmox.lan:8006
	VerifyTLS bool   `yaml:"verify_tls" json:"verify_tls"` // self-signed PVE cert → false
	AuthMode  string `yaml:"auth_mode" json:"auth_mode"`   // "token" (default) | "password"
	Username  string `yaml:"username" json:"username"`     // password mode: user@realm (e.g. root@pam)
}

// Normalize migrates a legacy single-instance Proxmox config into Instances[0]
// so old configs keep working after the multi-instance upgrade.
func (p *Proxmox) Normalize() {
	if len(p.Instances) == 0 && p.BaseURL != "" {
		p.Instances = []ProxmoxInstance{{BaseURL: p.BaseURL, VerifyTLS: p.VerifyTLS, AuthMode: "token"}}
	}
	if len(p.Instances) > MaxProxmoxInstances {
		p.Instances = p.Instances[:MaxProxmoxInstances]
	}
	for i := range p.Instances {
		if p.Instances[i].AuthMode == "" {
			p.Instances[i].AuthMode = "token"
		}
	}
}

// DNS configures ingestion of authoritative name↔IP records from any local DNS:
// hosts-format / Unbound files (Pi-hole custom.list, dnsmasq, Unbound, /etc/hosts)
// and one optional DNS-server HTTP API (AdGuard Home / Pi-hole v6 / Technitium).
// Off by default. The server token/password is a secret (env TESSERA_DNS_SERVER_TOKEN).
type DNS struct {
	Enabled    bool     `yaml:"enabled"`
	HostsFiles []string `yaml:"hosts_files"`
	// HTTP-API server (blank type = files only).
	ServerType string        `yaml:"server_type"` // adguard | pihole | technitium
	ServerURL  string        `yaml:"server_url"`  // e.g. http://dns.lan:3000
	ServerUser string        `yaml:"server_user"` // AdGuard basic-auth user (others ignore)
	Interval   time.Duration `yaml:"interval"`
}

// DHCP configures ingestion of DHCP server lease tables (dnsmasq-family lease
// files for now). Off by default; lease files are read from the Tessera host's
// filesystem (no auth).
type DHCP struct {
	Enabled    bool          `yaml:"enabled"`
	LeaseFiles []string      `yaml:"lease_files"` // dnsmasq/Pi-hole/OpenWrt lease file paths
	Interval   time.Duration `yaml:"interval"`    // re-read cadence; 0 = default 5m
}

// Storage configures the persistence driver (§5).
type Storage struct {
	Driver string `yaml:"driver"` // sqlite (postgres swappable later)
	DSN    string `yaml:"dsn"`
}

// Secrets holds values that must never touch the config file or logs (§5).
type Secrets struct {
	UniFiUsername    string
	UniFiPassword    string
	UniFiAPIKey      string
	ProxmoxTokens    [MaxProxmoxInstances]string // per-instance PVE API tokens
	ProxmoxPasswords [MaxProxmoxInstances]string // per-instance PVE ticket passwords
	DNSServerToken   string                      // DNS-server API password/token (AdGuard/Pi-hole/Technitium)
	FingerbankKey    string
	SNMPCommunity    string
	APIToken         string // optional bearer token for the HTTP API (§M8)
	APIPasswordHash  string // bcrypt hash of the bootstrap admin password (§M9)
	SecretKey        string // master key for encrypting settings secrets at rest (§M10)
	AlertWebhookURL  string // destination URL for alert notifications (may carry a token)
}

// Alerts configures proactive notifications dispatched on reconciliation deltas.
// The destination URL is a secret (Secrets.AlertWebhookURL); everything else is
// plain config.
type Alerts struct {
	Enabled      bool   `yaml:"enabled"`
	Kind         string `yaml:"kind"` // webhook | slack | discord | ntfy
	NewDevice    bool   `yaml:"new_device"`
	Offline      bool   `yaml:"offline"`
	Online       bool   `yaml:"online"`
	IPChanged    bool   `yaml:"ip_changed"`
	Conflict     bool   `yaml:"conflict"`
	RiskyService bool   `yaml:"risky_service"`
}

// Default returns a Config populated with the §5 defaults, before file/env
// overlay.
func Default() Config {
	return Config{
		Sensor: Sensor{DedupeWindowMS: 50},
		ActiveProbe: ActiveProbe{
			// A default port list, deliberately short. Each entry earns its place
			// twice — as a service worth knowing about, and as the gate on an
			// identity probe:
			//
			//	22     SSH       — banner states the Linux distribution and release
			//	80     HTTP      — server banner
			//	443    HTTPS     — liveness on hosts that answer nothing else
			//	445    SMB       ┐ NTLMSSP challenge → Windows release + build
			//	3389   RDP       ┘
			//	161    SNMP      — sysName/sysDescr
			//	8006   Proxmox   — VE login page → hypervisor identity + version
			//	7000   AirPlay   ┐ /info → exact Apple model + OS build. A MAC
			//	49152  AirPlay   │ ANSWERS ON 7000, an iOS device on 49152 —
			//	5000   RAOP      ┘ 5000 is the classic AirTunes port, and DSM's
			//	62078  lockdownd — iOS Wi-Fi sync; listening proves iOS family
			//
			// An identity probe never opens a port the scan did not find, so a
			// port missing from this list silently disables the probe behind it.
			// That is exactly the "correct code that never ran" failure this
			// project keeps hitting, so the pairing is asserted in a test.
			//
			// To scan NO TCP ports, turn off discovery.active_tcp — that is the
			// switch for it. An empty list here (or in Settings) falls back to
			// this default rather than disabling the scan.
			TCPPorts: []int{22, 80, 443, 445, 3389, 161, 5000, 7000, 8006, 49152, 62078},
			Rate:     ProbeRate{MaxProbesPerSec: 20, CycleInterval: 15 * time.Minute},
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
		Proxmox: Proxmox{
			Enabled:      false,
			PollInterval: 5 * time.Minute,
		},
		DHCP: DHCP{
			Enabled:  false,
			Interval: 5 * time.Minute,
		},
		DNS: DNS{
			Enabled:  false,
			Interval: 5 * time.Minute,
		},
		Reconcile: Reconcile{
			StaleAfter:           24 * time.Hour,
			FreeAfter:            168 * time.Hour,
			ConfidenceHalfLife:   72 * time.Hour,
			CompactInterval:      6 * time.Hour,
			ForgetDormantEnabled: false,
			ForgetDormantDays:    30,
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
