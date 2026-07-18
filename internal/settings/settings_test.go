package settings

import (
	"context"
	"testing"

	"github.com/tessera/tessera/internal/config"
	"github.com/tessera/tessera/internal/secret"
)

// memStore is a trivial in-memory settings.Store for tests.
type memStore map[string]string

func (m memStore) SettingGet(_ context.Context, key string) (string, bool, error) {
	v, ok := m[key]
	return v, ok, nil
}
func (m memStore) SettingSet(_ context.Context, key, value string, _ bool) error {
	m[key] = value
	return nil
}

// TestProxmoxInstanceSecretAlignment locks the contract app.go relies on: an
// instance at index i must pair with the secret stored at index i, even when an
// interior slot is empty. This is the server half of the positional-secrets
// invariant (the UI must send instances positionally, never compacted).
func TestProxmoxInstanceSecretAlignment(t *testing.T) {
	cipher, err := secret.New(secret.GenerateKey())
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	store := memStore{}
	svc := New(store, cipher)
	ctx := context.Background()

	// Instances positioned at 0 and 2, with a deliberately-empty slot 1.
	ed := Editable{
		ProxmoxEnabled: true,
		ProxmoxInstances: []config.ProxmoxInstance{
			{Name: "primary", BaseURL: "https://pve0.lan:8006", AuthMode: "token"},
			{}, // empty interior slot
			{Name: "lab", BaseURL: "https://pve2.lan:8006", AuthMode: "password", Username: "monitor@pve"},
		},
	}
	if err := svc.SaveEditable(ctx, ed); err != nil {
		t.Fatalf("SaveEditable: %v", err)
	}

	tok0, tok2 := "root@pam!t=aaa", "root@pam!t=ccc"
	pass2 := "s3cret-2"
	in := SecretsInput{}
	in.ProxmoxTokens[0] = &tok0
	in.ProxmoxTokens[2] = &tok2
	in.ProxmoxPasswords[2] = &pass2
	if err := svc.SaveSecrets(ctx, in); err != nil {
		t.Fatalf("SaveSecrets: %v", err)
	}

	eff, err := svc.Effective(ctx, config.Default())
	if err != nil {
		t.Fatalf("Effective: %v", err)
	}

	if got := len(eff.Proxmox.Instances); got != 3 {
		t.Fatalf("got %d instances, want 3 (interior gap preserved)", got)
	}
	if eff.Proxmox.Instances[0].BaseURL != "https://pve0.lan:8006" {
		t.Errorf("instance 0 = %+v", eff.Proxmox.Instances[0])
	}
	if eff.Proxmox.Instances[2].BaseURL != "https://pve2.lan:8006" {
		t.Errorf("instance 2 = %+v", eff.Proxmox.Instances[2])
	}
	// The crux: each instance's secret is read from its own index.
	if eff.Secrets.ProxmoxTokens[0] != tok0 {
		t.Errorf("token[0] = %q, want %q", eff.Secrets.ProxmoxTokens[0], tok0)
	}
	if eff.Secrets.ProxmoxTokens[2] != tok2 {
		t.Errorf("token[2] = %q, want %q", eff.Secrets.ProxmoxTokens[2], tok2)
	}
	if eff.Secrets.ProxmoxPasswords[2] != pass2 {
		t.Errorf("password[2] = %q, want %q", eff.Secrets.ProxmoxPasswords[2], pass2)
	}
	// The empty slot's secrets stay empty — nothing bled across from a neighbour.
	if eff.Secrets.ProxmoxTokens[1] != "" || eff.Secrets.ProxmoxPasswords[1] != "" {
		t.Errorf("interior slot 1 should have no secrets, got token=%q pass=%q",
			eff.Secrets.ProxmoxTokens[1], eff.Secrets.ProxmoxPasswords[1])
	}
}

// TestProxmoxLegacySecretKey verifies instance 0 still decrypts from the legacy
// un-suffixed secret key (back-compat with single-instance configs).
func TestProxmoxLegacySecretKey(t *testing.T) {
	if secProxmoxToken(0) != "secret.proxmox_token" {
		t.Errorf("instance 0 token key = %q, want legacy secret.proxmox_token", secProxmoxToken(0))
	}
	if secProxmoxToken(1) != "secret.proxmox_token_1" {
		t.Errorf("instance 1 token key = %q, want secret.proxmox_token_1", secProxmoxToken(1))
	}
}
