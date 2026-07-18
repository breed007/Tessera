package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTemp(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "tessera.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadDefaultsAndOverlay(t *testing.T) {
	p := writeTemp(t, `
storage:
  driver: sqlite
  dsn: test.db
unifi:
  poll_interval: 10m
`)
	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Storage.DSN != "test.db" {
		t.Errorf("dsn override not applied: %q", cfg.Storage.DSN)
	}
	// Defaults survive where the file is silent.
	if cfg.Fingerbank.Enabled {
		t.Error("fingerbank should default to disabled (privacy)")
	}
	if cfg.Fingerbank.Rate.MaxPerHour != 250 {
		t.Errorf("default fingerbank rate not applied: %d", cfg.Fingerbank.Rate.MaxPerHour)
	}
	if cfg.UniFi.PollInterval.Minutes() != 10 {
		t.Errorf("poll_interval override not applied: %v", cfg.UniFi.PollInterval)
	}
}

func TestSecretsComeFromEnvOnly(t *testing.T) {
	// A secret-looking value placed in the FILE must NOT populate Secrets.
	p := writeTemp(t, `
storage: {driver: sqlite, dsn: test.db}
`)
	t.Setenv(EnvUniFiPassword, "from-env")
	t.Setenv(EnvFingerbankKey, "fb-key")
	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Secrets.UniFiPassword != "from-env" {
		t.Errorf("expected secret from env, got %q", cfg.Secrets.UniFiPassword)
	}
	if cfg.Secrets.FingerbankKey != "fb-key" {
		t.Errorf("expected fingerbank key from env, got %q", cfg.Secrets.FingerbankKey)
	}
}

func TestValidateRejectsUnscopedProbe(t *testing.T) {
	// §4.2: active prober enabled with no subnets must be rejected.
	p := writeTemp(t, `
storage: {driver: sqlite, dsn: test.db}
active_probe:
  enabled: true
  subnets: []
`)
	if _, err := Load(p); err == nil {
		t.Fatal("expected validation error for unscoped active probe")
	}
}

func TestSensorEnabledGating(t *testing.T) {
	// Default off: sources may be listed as templates without capturing.
	p := writeTemp(t, `
storage: {driver: sqlite, dsn: test.db}
sensor:
  sources:
    - {kind: span, nic: eth1}
`)
	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Sensor.Enabled {
		t.Error("sensor should default to disabled")
	}

	// Enabled with no sources is a misconfiguration.
	bad := writeTemp(t, `
storage: {driver: sqlite, dsn: test.db}
sensor:
  enabled: true
  sources: []
`)
	if _, err := Load(bad); err == nil {
		t.Error("sensor.enabled=true with no sources should be rejected")
	}

	// Enabled with a source is fine.
	ok := writeTemp(t, `
storage: {driver: sqlite, dsn: test.db}
sensor:
  enabled: true
  sources:
    - {kind: interface, nic: eth0}
`)
	if _, err := Load(ok); err != nil {
		t.Errorf("enabled sensor with a source should load: %v", err)
	}
}

func TestLoadMissingFileUsesDefaults(t *testing.T) {
	// A non-existent config path must NOT error — the daemon runs on defaults
	// (everything else is configured in the UI).
	cfg, err := Load(filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	if err != nil {
		t.Fatalf("missing config should load defaults, got error: %v", err)
	}
	if cfg.API.ListenAddr != "0.0.0.0:10404" {
		t.Errorf("default listen_addr = %q, want 0.0.0.0:10404", cfg.API.ListenAddr)
	}
	// A present-but-malformed file is still an error.
	bad := writeTemp(t, "api: { this is : not valid : yaml ]")
	if _, err := Load(bad); err == nil {
		t.Error("malformed config should error")
	}
}

func TestValidateRejectsUnknownDriver(t *testing.T) {
	p := writeTemp(t, `
storage: {driver: mysql, dsn: x}
`)
	if _, err := Load(p); err == nil {
		t.Fatal("expected validation error for unsupported driver")
	}
}

func TestProxmoxNormalizeLegacy(t *testing.T) {
	// A pre-multi-instance config with the old top-level base_url should migrate
	// into Instances[0] with token auth.
	p := &Proxmox{Enabled: true, BaseURL: "https://pve.lan:8006", VerifyTLS: true}
	p.Normalize()
	if len(p.Instances) != 1 {
		t.Fatalf("got %d instances, want 1", len(p.Instances))
	}
	if p.Instances[0].BaseURL != "https://pve.lan:8006" || !p.Instances[0].VerifyTLS || p.Instances[0].AuthMode != "token" {
		t.Fatalf("bad migration: %+v", p.Instances[0])
	}
}

func TestProxmoxNormalizeCapAndDefault(t *testing.T) {
	p := &Proxmox{}
	for i := 0; i < 8; i++ {
		p.Instances = append(p.Instances, ProxmoxInstance{BaseURL: "https://h"})
	}
	p.Normalize()
	if len(p.Instances) != MaxProxmoxInstances {
		t.Fatalf("got %d instances, want cap %d", len(p.Instances), MaxProxmoxInstances)
	}
	for i, inst := range p.Instances {
		if inst.AuthMode != "token" {
			t.Errorf("instance %d auth_mode = %q, want defaulted to token", i, inst.AuthMode)
		}
	}
}

func TestValidateDNSServerHalfConfigured(t *testing.T) {
	base := func() Config {
		c := Default()
		c.Storage.Driver, c.Storage.DSN = "sqlite", "x.db"
		c.DNS.Enabled = true
		return c
	}
	// URL without a type → error.
	c := base()
	c.DNS.ServerURL = "http://dns.lan:3000"
	if err := c.Validate(); err == nil {
		t.Error("expected error for server_url without server_type")
	}
	// Type without a URL → error.
	c = base()
	c.DNS.ServerType = "adguard"
	if err := c.Validate(); err == nil {
		t.Error("expected error for server_type without server_url")
	}
	// Both set → ok.
	c = base()
	c.DNS.ServerType, c.DNS.ServerURL = "adguard", "http://dns.lan:3000"
	if err := c.Validate(); err != nil {
		t.Errorf("both set should validate: %v", err)
	}
	// Neither set (files-only) → ok.
	c = base()
	if err := c.Validate(); err != nil {
		t.Errorf("files-only DNS should validate: %v", err)
	}
	// Bogus type → error.
	c = base()
	c.DNS.ServerType, c.DNS.ServerURL = "bind9", "http://dns.lan"
	if err := c.Validate(); err == nil {
		t.Error("expected error for unknown server_type")
	}
}
