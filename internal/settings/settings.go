// Package settings makes a subset of configuration runtime-editable via the UI
// (§M10), persisted in the database and overlaid on the file config. Non-secret
// values are stored as one JSON document; secret credentials are stored in
// separate rows, encrypted with the master key (secret.Cipher).
package settings

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/tessera/tessera/internal/config"
	"github.com/tessera/tessera/internal/secret"
)

// Store is the key/value persistence the service needs.
type Store interface {
	SettingGet(ctx context.Context, key string) (value string, ok bool, err error)
	SettingSet(ctx context.Context, key, value string, isSecret bool) error
}

const keyConfig = "config"

// secret row keys.
const (
	secUniFiUser  = "secret.unifi_username"
	secUniFiPass  = "secret.unifi_password"
	secUniFiKey   = "secret.unifi_api_key"
	secDNSToken   = "secret.dns_server_token"
	secSNMP       = "secret.snmp_community"
	secFingerbank = "secret.fingerbank_key"
	secAlertURL   = "secret.alert_webhook_url"
)

// Per-instance Proxmox secret keys. Instance 0 keeps the legacy un-suffixed key
// so a single-instance config configured before the multi-instance upgrade still
// decrypts.
func secProxmoxToken(i int) string {
	if i == 0 {
		return "secret.proxmox_token"
	}
	return fmt.Sprintf("secret.proxmox_token_%d", i)
}

func secProxmoxPassword(i int) string {
	if i == 0 {
		return "secret.proxmox_password"
	}
	return fmt.Sprintf("secret.proxmox_password_%d", i)
}

// Editable is the UI-editable surface of the configuration (non-secret).
type Editable struct {
	APIListenAddr string `json:"api_listen_addr"`
	TLSEnabled    bool   `json:"tls_enabled"`

	UniFiEnabled    bool   `json:"unifi_enabled"`
	UniFiBaseURL    string `json:"unifi_base_url"`
	UniFiPathPrefix string `json:"unifi_path_prefix"`
	UniFiSite       string `json:"unifi_site"`
	UniFiVerifyTLS  bool   `json:"unifi_verify_tls"`

	ProxmoxEnabled   bool                     `json:"proxmox_enabled"`
	ProxmoxInstances []config.ProxmoxInstance `json:"proxmox_instances"`
	// Deprecated single-instance fields (migrated into ProxmoxInstances[0]).
	ProxmoxBaseURL   string `json:"proxmox_base_url,omitempty"`
	ProxmoxVerifyTLS bool   `json:"proxmox_verify_tls,omitempty"`

	FingerbankEnabled bool   `json:"fingerbank_enabled"`
	FingerbankMode    string `json:"fingerbank_mode"`

	ActiveProbeEnabled   bool     `json:"active_probe_enabled"`
	ActiveProbeSubnets   []string `json:"active_probe_subnets"`
	ActiveProbeTCPPorts  []int    `json:"active_probe_tcp_ports"`
	ActiveProbeUDPPorts  []int    `json:"active_probe_udp_ports"`
	ActiveProbeICMP      bool     `json:"active_probe_icmp"`
	ActiveProbeInterface string   `json:"active_probe_interface"`
	SNMPCommunities      []string `json:"snmp_communities"` // visible, multi-valued (low-sensitivity, operator-managed)

	SensorEnabled bool `json:"sensor_enabled"`

	// DHCP lease ingestion (dnsmasq-family lease files).
	DHCPEnabled    bool     `json:"dhcp_enabled"`
	DHCPLeaseFiles []string `json:"dhcp_lease_files"`

	// DNS records ingestion (local files + one DNS-server API).
	DNSEnabled    bool     `json:"dns_enabled"`
	DNSHostsFiles []string `json:"dns_hosts_files"`
	DNSServerType string   `json:"dns_server_type"` // adguard | pihole | technitium
	DNSServerURL  string   `json:"dns_server_url"`
	DNSServerUser string   `json:"dns_server_user"`

	// Auto-prune dormant devices (off by default; days default 30).
	ForgetDormantEnabled bool `json:"forget_dormant_enabled"`
	ForgetDormantDays    int  `json:"forget_dormant_days"`

	// Alerts (the webhook URL itself is a secret; see SecretsInput.AlertURL).
	AlertsEnabled     bool   `json:"alerts_enabled"`
	AlertsKind        string `json:"alerts_kind"`
	AlertNewDevice    bool   `json:"alert_new_device"`
	AlertOffline      bool   `json:"alert_offline"`
	AlertOnline       bool   `json:"alert_online"`
	AlertIPChanged    bool   `json:"alert_ip_changed"`
	AlertConflict     bool   `json:"alert_conflict"`
	AlertRiskyService bool   `json:"alert_risky_service"`

	// Discovery techniques (per-protocol toggles; all default on). Passive_*
	// apply when the sensor is enabled; the rest when the active prober is.
	DiscPassiveARP       bool `json:"disc_passive_arp"`
	DiscPassiveDHCP      bool `json:"disc_passive_dhcp"`
	DiscPassiveMDNS      bool `json:"disc_passive_mdns"`
	DiscPassiveSSDP      bool `json:"disc_passive_ssdp"`
	DiscPassiveNetBIOS   bool `json:"disc_passive_netbios"`
	DiscActiveICMP       bool `json:"disc_active_icmp"`
	DiscActiveTCP        bool `json:"disc_active_tcp"`
	DiscActiveUDP        bool `json:"disc_active_udp"`
	DiscActiveBanners    bool `json:"disc_active_banners"`
	DiscActiveReverseDNS bool `json:"disc_active_reverse_dns"`
	DiscActiveARPTable   bool `json:"disc_active_arp_table"`
	DiscActiveSNMP       bool `json:"disc_active_snmp"`
	DiscActiveMDNS       bool `json:"disc_active_mdns"`
	DiscActiveMedia      bool `json:"disc_active_media"`
	DiscTCPBehavioral    bool `json:"disc_tcp_behavioral"`
	DiscThoroughWake     bool `json:"disc_thorough_wake"`
}

// SecretsInput carries secret values from the UI. An empty field means "leave
// unchanged"; a non-empty field replaces the stored (encrypted) value.
type SecretsInput struct {
	UniFiUsername    *string                             `json:"unifi_username,omitempty"`
	UniFiPassword    *string                             `json:"unifi_password,omitempty"`
	UniFiAPIKey      *string                             `json:"unifi_api_key,omitempty"`
	ProxmoxTokens    [config.MaxProxmoxInstances]*string `json:"proxmox_tokens,omitempty"`
	ProxmoxPasswords [config.MaxProxmoxInstances]*string `json:"proxmox_passwords,omitempty"`
	DNSServerToken   *string                             `json:"dns_server_token,omitempty"`
	SNMPCommunity    *string                             `json:"snmp_community,omitempty"`
	FingerbankKey    *string                             `json:"fingerbank_key,omitempty"`
	AlertURL         *string                             `json:"alert_url,omitempty"`
}

// SecretFlags reports which secrets are currently set (without revealing them).
type SecretFlags struct {
	UniFiUsername    bool                             `json:"unifi_username_set"`
	UniFiPassword    bool                             `json:"unifi_password_set"`
	UniFiAPIKey      bool                             `json:"unifi_api_key_set"`
	ProxmoxTokens    [config.MaxProxmoxInstances]bool `json:"proxmox_tokens_set"`
	ProxmoxPasswords [config.MaxProxmoxInstances]bool `json:"proxmox_passwords_set"`
	DNSServerToken   bool                             `json:"dns_server_token_set"`
	SNMPCommunity    bool                             `json:"snmp_community_set"`
	FingerbankKey    bool                             `json:"fingerbank_key_set"`
	AlertURL         bool                             `json:"alert_url_set"`
}

// Service reads/writes the editable settings, applying encryption for secrets.
type Service struct {
	store  Store
	cipher *secret.Cipher
}

func New(store Store, cipher *secret.Cipher) *Service {
	return &Service{store: store, cipher: cipher}
}

// CanStoreSecrets reports whether a master key is configured (secrets editable).
func (s *Service) CanStoreSecrets() bool { return s.cipher.Enabled() }

// Effective overlays the persisted settings onto base and returns the config the
// daemon should run with (including decrypted secrets in cfg.Secrets).
func (s *Service) Effective(ctx context.Context, base config.Config) (config.Config, error) {
	if raw, ok, err := s.store.SettingGet(ctx, keyConfig); err != nil {
		return base, err
	} else if ok && raw != "" {
		var e Editable
		if err := json.Unmarshal([]byte(raw), &e); err == nil {
			applyEditable(&base, e)
		}
	}
	// Decrypt secret overrides (DB wins over env when set).
	dsts := map[string]*string{
		secUniFiUser: &base.Secrets.UniFiUsername, secUniFiPass: &base.Secrets.UniFiPassword,
		secUniFiKey: &base.Secrets.UniFiAPIKey, secDNSToken: &base.Secrets.DNSServerToken,
		secSNMP: &base.Secrets.SNMPCommunity, secFingerbank: &base.Secrets.FingerbankKey, secAlertURL: &base.Secrets.AlertWebhookURL,
	}
	for i := 0; i < config.MaxProxmoxInstances; i++ {
		dsts[secProxmoxToken(i)] = &base.Secrets.ProxmoxTokens[i]
		dsts[secProxmoxPassword(i)] = &base.Secrets.ProxmoxPasswords[i]
	}
	for key, dst := range dsts {
		if v, ok, _ := s.store.SettingGet(ctx, key); ok && v != "" {
			if plain, err := s.cipher.Open(v); err == nil && plain != "" {
				*dst = plain
			} else if err != nil {
				// A stored secret that won't decrypt (typically a restored backup
				// from another server with a different master key). Don't silently
				// drop it — that turns into "the UniFi poller just stopped working".
				slog.Warn("settings: stored secret could not be decrypted — check the master key (secret.key)", "key", key)
			}
		}
	}
	return base, nil
}

// DecryptFailures counts persisted secrets that fail to decrypt with the current
// master key (e.g. a backup restored onto a server with a different key).
func (s *Service) DecryptFailures(ctx context.Context) int {
	n := 0
	keys := []string{secUniFiUser, secUniFiPass, secUniFiKey, secDNSToken, secSNMP, secFingerbank, secAlertURL}
	for i := 0; i < config.MaxProxmoxInstances; i++ {
		keys = append(keys, secProxmoxToken(i), secProxmoxPassword(i))
	}
	for _, key := range keys {
		if v, ok, _ := s.store.SettingGet(ctx, key); ok && v != "" {
			if _, err := s.cipher.Open(v); err != nil {
				n++
			}
		}
	}
	return n
}

// Current returns the editable view for the UI plus which secrets are set.
func (s *Service) Current(ctx context.Context, base config.Config) (Editable, SecretFlags, error) {
	eff, err := s.Effective(ctx, base)
	if err != nil {
		return Editable{}, SecretFlags{}, err
	}
	return extractEditable(eff), s.secretFlags(ctx), nil
}

// SaveEditable persists the non-secret editable settings.
func (s *Service) SaveEditable(ctx context.Context, e Editable) error {
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	return s.store.SettingSet(ctx, keyConfig, string(b), false)
}

// SaveSecrets encrypts and stores any provided secret fields.
func (s *Service) SaveSecrets(ctx context.Context, in SecretsInput) error {
	vals := map[string]*string{
		secUniFiUser: in.UniFiUsername, secUniFiPass: in.UniFiPassword, secUniFiKey: in.UniFiAPIKey,
		secDNSToken: in.DNSServerToken,
		secSNMP:     in.SNMPCommunity, secFingerbank: in.FingerbankKey, secAlertURL: in.AlertURL,
	}
	for i := 0; i < config.MaxProxmoxInstances; i++ {
		vals[secProxmoxToken(i)] = in.ProxmoxTokens[i]
		vals[secProxmoxPassword(i)] = in.ProxmoxPasswords[i]
	}
	for key, val := range vals {
		if val == nil {
			continue
		}
		enc, err := s.cipher.Seal(*val)
		if err != nil {
			return err
		}
		if err := s.store.SettingSet(ctx, key, enc, true); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) secretFlags(ctx context.Context) SecretFlags {
	isSet := func(k string) bool { v, ok, _ := s.store.SettingGet(ctx, k); return ok && v != "" }
	f := SecretFlags{
		UniFiUsername: isSet(secUniFiUser), UniFiPassword: isSet(secUniFiPass), UniFiAPIKey: isSet(secUniFiKey),
		DNSServerToken: isSet(secDNSToken),
		SNMPCommunity:  isSet(secSNMP), FingerbankKey: isSet(secFingerbank), AlertURL: isSet(secAlertURL),
	}
	for i := 0; i < config.MaxProxmoxInstances; i++ {
		f.ProxmoxTokens[i] = isSet(secProxmoxToken(i))
		f.ProxmoxPasswords[i] = isSet(secProxmoxPassword(i))
	}
	return f
}

// applyEditable overlays the editable values onto a config.Config.
func applyEditable(c *config.Config, e Editable) {
	c.API.ListenAddr = e.APIListenAddr
	c.UniFi.Enabled = e.UniFiEnabled
	c.UniFi.BaseURL = e.UniFiBaseURL
	c.UniFi.PathPrefix = e.UniFiPathPrefix
	c.UniFi.Site = e.UniFiSite
	c.UniFi.VerifyTLS = e.UniFiVerifyTLS
	c.Proxmox.Enabled = e.ProxmoxEnabled
	c.Proxmox.Instances = e.ProxmoxInstances
	// Back-compat: a settings doc saved before multi-instance carried a single
	// base URL — fold it into instance 0.
	if len(c.Proxmox.Instances) == 0 && e.ProxmoxBaseURL != "" {
		c.Proxmox.Instances = []config.ProxmoxInstance{{BaseURL: e.ProxmoxBaseURL, VerifyTLS: e.ProxmoxVerifyTLS, AuthMode: "token"}}
	}
	c.Proxmox.Normalize()
	c.Fingerbank.Enabled = e.FingerbankEnabled
	if e.FingerbankMode != "" {
		c.Fingerbank.Mode = e.FingerbankMode
	}
	c.ActiveProbe.Enabled = e.ActiveProbeEnabled
	c.ActiveProbe.Subnets = e.ActiveProbeSubnets
	if len(e.ActiveProbeTCPPorts) > 0 {
		c.ActiveProbe.TCPPorts = e.ActiveProbeTCPPorts
	}
	c.ActiveProbe.UDPPorts = e.ActiveProbeUDPPorts
	c.ActiveProbe.ICMP = e.ActiveProbeICMP
	c.ActiveProbe.Interface = e.ActiveProbeInterface
	c.ActiveProbe.SNMPCommunities = e.SNMPCommunities
	c.Sensor.Enabled = e.SensorEnabled
	c.DHCP.Enabled = e.DHCPEnabled
	c.DHCP.LeaseFiles = e.DHCPLeaseFiles
	c.DNS.Enabled = e.DNSEnabled
	c.DNS.HostsFiles = e.DNSHostsFiles
	c.DNS.ServerType = e.DNSServerType
	c.DNS.ServerURL = e.DNSServerURL
	c.DNS.ServerUser = e.DNSServerUser
	c.Reconcile.ForgetDormantEnabled = e.ForgetDormantEnabled
	if e.ForgetDormantDays > 0 {
		c.Reconcile.ForgetDormantDays = e.ForgetDormantDays
	}
	c.Alerts = config.Alerts{
		Enabled: e.AlertsEnabled, Kind: e.AlertsKind,
		NewDevice: e.AlertNewDevice, Offline: e.AlertOffline, Online: e.AlertOnline,
		IPChanged: e.AlertIPChanged, Conflict: e.AlertConflict, RiskyService: e.AlertRiskyService,
	}

	b := func(v bool) *bool { return &v }
	c.Discovery = config.Discovery{
		PassiveARP: b(e.DiscPassiveARP), PassiveDHCP: b(e.DiscPassiveDHCP), PassiveMDNS: b(e.DiscPassiveMDNS),
		PassiveSSDP: b(e.DiscPassiveSSDP), PassiveNetBIOS: b(e.DiscPassiveNetBIOS),
		ActiveICMP: b(e.DiscActiveICMP), ActiveTCP: b(e.DiscActiveTCP), ActiveUDP: b(e.DiscActiveUDP),
		ActiveBanners:    b(e.DiscActiveBanners),
		ActiveReverseDNS: b(e.DiscActiveReverseDNS), ActiveARPTable: b(e.DiscActiveARPTable),
		ActiveSNMP: b(e.DiscActiveSNMP), ActiveMDNS: b(e.DiscActiveMDNS), ActiveMedia: b(e.DiscActiveMedia),
		TCPBehavioral: b(e.DiscTCPBehavioral), ThoroughWake: b(e.DiscThoroughWake),
	}
}

func extractEditable(c config.Config) Editable {
	d := c.Discovery.Resolve()
	return Editable{
		APIListenAddr:        c.API.ListenAddr,
		UniFiEnabled:         c.UniFi.Enabled,
		UniFiBaseURL:         c.UniFi.BaseURL,
		UniFiPathPrefix:      c.UniFi.PathPrefix,
		UniFiSite:            c.UniFi.Site,
		UniFiVerifyTLS:       c.UniFi.VerifyTLS,
		ProxmoxEnabled:       c.Proxmox.Enabled,
		ProxmoxInstances:     c.Proxmox.Instances,
		FingerbankEnabled:    c.Fingerbank.Enabled,
		FingerbankMode:       c.Fingerbank.Mode,
		ActiveProbeEnabled:   c.ActiveProbe.Enabled,
		ActiveProbeSubnets:   c.ActiveProbe.Subnets,
		ActiveProbeTCPPorts:  c.ActiveProbe.TCPPorts,
		ActiveProbeUDPPorts:  c.ActiveProbe.UDPPorts,
		ActiveProbeICMP:      c.ActiveProbe.ICMP,
		ActiveProbeInterface: c.ActiveProbe.Interface,
		SNMPCommunities:      c.ActiveProbe.SNMPCommunities,
		AlertsEnabled:        c.Alerts.Enabled,
		AlertsKind:           c.Alerts.Kind,
		AlertNewDevice:       c.Alerts.NewDevice,
		AlertOffline:         c.Alerts.Offline,
		AlertOnline:          c.Alerts.Online,
		AlertIPChanged:       c.Alerts.IPChanged,
		AlertConflict:        c.Alerts.Conflict,
		AlertRiskyService:    c.Alerts.RiskyService,
		SensorEnabled:        c.Sensor.Enabled,

		DHCPEnabled:    c.DHCP.Enabled,
		DHCPLeaseFiles: c.DHCP.LeaseFiles,

		DNSEnabled:    c.DNS.Enabled,
		DNSHostsFiles: c.DNS.HostsFiles,
		DNSServerType: c.DNS.ServerType,
		DNSServerURL:  c.DNS.ServerURL,
		DNSServerUser: c.DNS.ServerUser,

		ForgetDormantEnabled: c.Reconcile.ForgetDormantEnabled,
		ForgetDormantDays:    c.Reconcile.ForgetDormantDays,

		DiscPassiveARP:       d.PassiveARP,
		DiscPassiveDHCP:      d.PassiveDHCP,
		DiscPassiveMDNS:      d.PassiveMDNS,
		DiscPassiveSSDP:      d.PassiveSSDP,
		DiscPassiveNetBIOS:   d.PassiveNetBIOS,
		DiscActiveICMP:       d.ActiveICMP,
		DiscActiveTCP:        d.ActiveTCP,
		DiscActiveUDP:        d.ActiveUDP,
		DiscActiveBanners:    d.ActiveBanners,
		DiscActiveReverseDNS: d.ActiveReverseDNS,
		DiscActiveARPTable:   d.ActiveARPTable,
		DiscActiveSNMP:       d.ActiveSNMP,
		DiscActiveMDNS:       d.ActiveMDNS,
		DiscActiveMedia:      d.ActiveMedia,
		DiscTCPBehavioral:    d.TCPBehavioral,
		DiscThoroughWake:     d.ThoroughWake,
	}
}
