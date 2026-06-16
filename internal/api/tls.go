package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// ensureTLS returns cert/key file paths for HTTPS. If the operator supplied
// CertFile/KeyFile, those are used. Otherwise a self-signed cert is generated
// once and cached in the data dir (§M10) so credentials aren't sent in cleartext.
func (s *Server) ensureTLS() (certFile, keyFile string, err error) {
	if s.tls.CertFile != "" && s.tls.KeyFile != "" {
		return s.tls.CertFile, s.tls.KeyFile, nil
	}
	dir := s.dataDir
	if dir == "" {
		dir = "."
	}
	tlsDir := filepath.Join(dir, "tls")
	cert := filepath.Join(tlsDir, "cert.pem")
	key := filepath.Join(tlsDir, "key.pem")
	if fileExists(cert) && fileExists(key) {
		return cert, key, nil
	}
	if err := os.MkdirAll(tlsDir, 0o750); err != nil {
		return "", "", err
	}
	if err := generateSelfSigned(cert, key); err != nil {
		return "", "", err
	}
	s.log.Info("generated self-signed TLS certificate", "dir", tlsDir)
	return cert, key, nil
}

func generateSelfSigned(certPath, keyPath string) error {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "tessera"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"tessera", "localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return err
	}
	if err := writePEM(certPath, "CERTIFICATE", der, 0o644); err != nil {
		return err
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return err
	}
	return writePEM(keyPath, "EC PRIVATE KEY", keyDER, 0o600)
}

func writePEM(path, blockType string, der []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return fmt.Errorf("api: write %s: %w", path, err)
	}
	defer f.Close()
	return pem.Encode(f, &pem.Block{Type: blockType, Bytes: der})
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
