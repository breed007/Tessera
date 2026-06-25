// Package settings makes a subset of configuration runtime-editable via the UI
// (§M10), persisted in the database and overlaid on the file config. Non-secret
// values are stored as one JSON document; secret credentials are stored in
// separate rows, encrypted with the master key (secret.Cipher).
package settings

import (
	"context"
	"encoding/json"

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
	secSNMP       = "secret.snmp_community"
	secFingerbank = "secret.fingerbank_key"
	secAlertURL   = "secret.alert_webhook_url"
)

// Editable is the UI-editable surface of the configuration (non-secret).
type Editable struct {
	APIListenAddr string `json:"api_listen_addr"`
	TLSEnabled    bool   `json:"tls_enabled"`

	UniFiEnabled    bool   `json:"unifi_enabled"`
	UniFiBaseURL    string `json:"unifi_base_url"`
	UniFiPathPrefix string `json:"unifi_path_prefix"`
	UniFiSite       string `json:"unifi_site"`
	UniFiVerifyTLS  bool   `json:"unifi_verify_tls"`

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

	// Auto-prune dormant devices (off by default; days default 30).
	ForgetDormantEnabled bool `json:"forget_dormant_enabled"`
	ForgetDormantDays    int  `json:"forget_dormant_days"`

	// Alerts (the webhook URL itself is a secret; see SecretsInput.AlertURL).
	AlertsEnabled   bool   `json:"alerts_enabled"`
	AlertsKind      string `json:"alerts_kind"`
	AlertNewDevice    bool `json:"alert_new_device"`
	AlertOffline      bool `json:"alert_offline"`
	AlertOnline       bool `json:"alert_online"`
	AlertIPChanged    bool `json:"alert_ip_changed"`
	AlertConflict     bool `json:"alert_conflict"`
	AlertRiskyService bool `json:"alert_risky_service"`

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
	DiscTCPBehavioral    bool `json:"disc_tcp_behavioral"`
	DiscThoroughWake     bool `json:"disc_thorough_wake"`
}

// SecretsInput carries secret values from the UI. An empty field means "leave
// unchanged"; a non-empty field replaces the stored (encrypted) value.
type SecretsInput struct {
	UniFiUsername *string `json:"unifi_username,omitempty"`
	UniFiPassword *string `json:"unifi_password,omitempty"`
	UniFiAPIKey   *string `json:"unifi_api_key,omitempty"`
	SNMPCommunity *string `json:"snmp_community,omitempty"`
	FingerbankKey *string `json:"fingerbank_key,omitempty"`
	AlertURL      *string `json:"alert_url,omitempty"`
}

// SecretFlags reports which secrets are currently set (without revealing them).
type SecretFlags struct {
	UniFiUsername bool `json:"unifi_username_set"`
	UniFiPassword bool `json:"unifi_password_set"`
	UniFiAPIKey   bool `json:"unifi_api_key_set"`
	SNMPCommunity bool `json:"snmp_community_set"`
	FingerbankKey bool `json:"fingerbank_key_set"`
	AlertURL      bool `json:"alert_url_set"`
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
	for key, dst := range map[string]*string{
		secUniFiUser: &base.Secrets.UniFiUsername, secUniFiPass: &base.Secrets.UniFiPassword,
		secUniFiKey: &base.Secrets.UniFiAPIKey, secSNMP: &base.Secrets.SNMPCommunity,
		secFingerbank: &base.Secrets.FingerbankKey, secAlertURL: &base.Secrets.AlertWebhookURL,
	} {
		if v, ok, _ := s.store.SettingGet(ctx, key); ok && v != "" {
			if plain, err := s.cipher.Open(v); err == nil && plain != "" {
				*dst = plain
			}
		}
	}
	return base, nil
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
	for key, val := range map[string]*string{
		secUniFiUser: in.UniFiUsername, secUniFiPass: in.UniFiPassword, secUniFiKey: in.UniFiAPIKey,
		secSNMP: in.SNMPCommunity, secFingerbank: in.FingerbankKey, secAlertURL: in.AlertURL,
	} {
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
	return SecretFlags{
		UniFiUsername: isSet(secUniFiUser), UniFiPassword: isSet(secUniFiPass), UniFiAPIKey: isSet(secUniFiKey),
		SNMPCommunity: isSet(secSNMP), FingerbankKey: isSet(secFingerbank), AlertURL: isSet(secAlertURL),
	}
}

// applyEditable overlays the editable values onto a config.Config.
func applyEditable(c *config.Config, e Editable) {
	c.API.ListenAddr = e.APIListenAddr
	c.UniFi.Enabled = e.UniFiEnabled
	c.UniFi.BaseURL = e.UniFiBaseURL
	c.UniFi.PathPrefix = e.UniFiPathPrefix
	c.UniFi.Site = e.UniFiSite
	c.UniFi.VerifyTLS = e.UniFiVerifyTLS
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
		ActiveSNMP: b(e.DiscActiveSNMP), TCPBehavioral: b(e.DiscTCPBehavioral), ThoroughWake: b(e.DiscThoroughWake),
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
		DiscTCPBehavioral:    d.TCPBehavioral,
		DiscThoroughWake:     d.ThoroughWake,
	}
}
