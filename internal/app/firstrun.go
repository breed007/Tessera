package app

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/tessera/tessera/internal/secret"
)

// loadOrCreateMasterKey returns the settings-secret master key. When no key is
// supplied via env, one is generated and persisted in the data dir (0600) so
// secrets-at-rest works out of the box for .deb/Docker first runs without an env
// var to manage. The operator can still override with TESSERA_SECRET_KEY or
// back up the file. (§M11)
func loadOrCreateMasterKey(dataDir string) (string, error) {
	path := filepath.Join(dataDir, "secret.key")
	if b, err := os.ReadFile(path); err == nil {
		if k := strings.TrimSpace(string(b)); k != "" {
			return k, nil
		}
	}
	key := secret.GenerateKey()
	if err := os.MkdirAll(dataDir, 0o750); err != nil {
		return "", err
	}
	if err := os.WriteFile(path, []byte(key+"\n"), 0o600); err != nil {
		return "", fmt.Errorf("app: write master key: %w", err)
	}
	return key, nil
}

// newSetupToken generates the one-time first-run setup token and persists it to a
// root/tessera-only file (also logged) so completing first-run setup requires
// host access — preventing a stranger on the LAN from claiming the admin account.
func newSetupToken(dataDir string) (token, file string, err error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	token = hex.EncodeToString(b)
	file = filepath.Join(dataDir, "setup-token")
	if err := os.MkdirAll(dataDir, 0o750); err != nil {
		return "", "", err
	}
	if err := os.WriteFile(file, []byte(token+"\n"), 0o600); err != nil {
		return "", "", err
	}
	return token, file, nil
}
