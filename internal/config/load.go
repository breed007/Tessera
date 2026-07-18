package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Environment variable names for secrets (§5). These are the ONLY way secrets
// enter the process.
const (
	EnvUniFiUsername   = "TESSERA_UNIFI_USERNAME"
	EnvUniFiPassword   = "TESSERA_UNIFI_PASSWORD"
	EnvUniFiAPIKey     = "TESSERA_UNIFI_API_KEY"
	EnvProxmoxToken    = "TESSERA_PROXMOX_TOKEN"
	EnvDNSServerToken  = "TESSERA_DNS_SERVER_TOKEN"
	EnvFingerbankKey   = "TESSERA_FINGERBANK_KEY"
	EnvSNMPCommunity   = "TESSERA_SNMP_COMMUNITY"
	EnvAPIToken        = "TESSERA_API_TOKEN"
	EnvAPIPasswordHash = "TESSERA_API_PASSWORD_HASH"
	EnvSecretKey       = "TESSERA_SECRET_KEY"
	EnvAlertWebhookURL = "TESSERA_ALERT_WEBHOOK_URL"
)

// Load reads config from path, overlaying onto the defaults, then pulls secrets
// from the environment. A MISSING file is not an error — Tessera runs on
// defaults (and everything else is configured in the UI), so installs work with
// no config at all. A present-but-malformed file IS an error (don't silently
// ignore the operator's intent).
func Load(path string) (Config, error) {
	cfg := Default()

	if path != "" {
		data, err := os.ReadFile(path)
		switch {
		case os.IsNotExist(err):
			// No file → defaults. Fall through to env + validate.
		case err != nil:
			return Config{}, fmt.Errorf("config: read %q: %w", path, err)
		default:
			// Overlay file values onto defaults. Fields absent in the file keep
			// their default; the decoder writes only what's present.
			if err := yaml.Unmarshal(data, &cfg); err != nil {
				return Config{}, fmt.Errorf("config: parse %q: %w", path, err)
			}
		}
	}

	loadSecrets(&cfg)

	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// loadSecrets reads secrets from the environment into cfg.Secrets. Nothing here
// is ever written back to disk or logged.
func loadSecrets(cfg *Config) {
	cfg.Secrets = Secrets{
		UniFiUsername:   os.Getenv(EnvUniFiUsername),
		UniFiPassword:   os.Getenv(EnvUniFiPassword),
		UniFiAPIKey:     os.Getenv(EnvUniFiAPIKey),
		ProxmoxToken:    os.Getenv(EnvProxmoxToken),
		DNSServerToken:  os.Getenv(EnvDNSServerToken),
		FingerbankKey:   os.Getenv(EnvFingerbankKey),
		SNMPCommunity:   os.Getenv(EnvSNMPCommunity),
		APIToken:        os.Getenv(EnvAPIToken),
		APIPasswordHash: os.Getenv(EnvAPIPasswordHash),
		SecretKey:       os.Getenv(EnvSecretKey),
		AlertWebhookURL: os.Getenv(EnvAlertWebhookURL),
	}
}

// Validate enforces the safety invariants the spec calls out, most importantly
// the §4.2 rule that the active prober is never unscoped.
func (c Config) Validate() error {
	if c.ActiveProbe.Enabled && len(c.ActiveProbe.Subnets) == 0 {
		return fmt.Errorf("config: active_probe.enabled is true but subnets is empty — " +
			"the prober must be explicitly scoped, never unscoped (§4.2)")
	}
	switch c.Storage.Driver {
	case "sqlite":
		if c.Storage.DSN == "" {
			return fmt.Errorf("config: storage.dsn is required for sqlite")
		}
	case "":
		return fmt.Errorf("config: storage.driver is required")
	default:
		return fmt.Errorf("config: unsupported storage.driver %q (only sqlite in v1)", c.Storage.Driver)
	}
	switch c.Fingerbank.Mode {
	case "api", "local_db", "off", "":
	default:
		return fmt.Errorf("config: invalid fingerbank.mode %q (api|local_db|off)", c.Fingerbank.Mode)
	}
	if c.Sensor.Enabled && len(c.Sensor.Sources) == 0 {
		return fmt.Errorf("config: sensor.enabled is true but no sources are configured — " +
			"add at least one interface/span source, or set sensor.enabled: false")
	}
	for _, s := range c.Sensor.Sources {
		if s.Kind != "interface" && s.Kind != "span" {
			return fmt.Errorf("config: sensor source kind %q must be 'interface' or 'span'", s.Kind)
		}
	}
	return nil
}
