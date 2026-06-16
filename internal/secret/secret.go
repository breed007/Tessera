// Package secret encrypts settings secrets at rest (§M10). UI-entered
// credentials (UniFi password, SNMP community, Fingerbank key) are stored in the
// database encrypted with AES-256-GCM under a single master key supplied via the
// environment (TESSERA_SECRET_KEY) — so the only plaintext secret on the host
// stays that one key, and everything else is UI-managed.
package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
)

// Cipher seals and opens secret values. A nil/zero Cipher is "disabled": Enabled
// reports false and Seal/Open refuse, so the rest of the system can fall back to
// env-only secrets when no key is configured.
type Cipher struct {
	aead cipher.AEAD
}

// New builds a Cipher from a 32-byte key encoded as hex (64 chars) or base64.
// An empty key yields a disabled Cipher (no error) so the daemon still runs.
func New(key string) (*Cipher, error) {
	if key == "" {
		return &Cipher{}, nil
	}
	raw, err := decodeKey(key)
	if err != nil {
		return nil, err
	}
	if len(raw) != 32 {
		return nil, fmt.Errorf("secret: key must be 32 bytes (got %d)", len(raw))
	}
	block, err := aes.NewCipher(raw)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Cipher{aead: aead}, nil
}

// Enabled reports whether a key is configured.
func (c *Cipher) Enabled() bool { return c != nil && c.aead != nil }

// Seal encrypts plaintext and returns base64(nonce || ciphertext). Empty input
// returns empty (so "unset" round-trips cleanly).
func (c *Cipher) Seal(plaintext string) (string, error) {
	if !c.Enabled() {
		return "", errors.New("secret: no encryption key configured (set TESSERA_SECRET_KEY)")
	}
	if plaintext == "" {
		return "", nil
	}
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ct := c.aead.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ct), nil
}

// Open decrypts a value produced by Seal.
func (c *Cipher) Open(encoded string) (string, error) {
	if encoded == "" {
		return "", nil
	}
	if !c.Enabled() {
		return "", errors.New("secret: no encryption key configured")
	}
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("secret: bad ciphertext: %w", err)
	}
	ns := c.aead.NonceSize()
	if len(data) < ns {
		return "", errors.New("secret: ciphertext too short")
	}
	pt, err := c.aead.Open(nil, data[:ns], data[ns:], nil)
	if err != nil {
		return "", fmt.Errorf("secret: decrypt failed (wrong key?): %w", err)
	}
	return string(pt), nil
}

// GenerateKey returns a new random 32-byte master key as hex (for `tessera setup`).
func GenerateKey() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func decodeKey(key string) ([]byte, error) {
	if b, err := hex.DecodeString(key); err == nil && len(b) == 32 {
		return b, nil
	}
	if b, err := base64.StdEncoding.DecodeString(key); err == nil {
		return b, nil
	}
	return nil, errors.New("secret: key must be 32-byte hex or base64")
}
