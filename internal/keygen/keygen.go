// Package keygen generates RSA and EC key pairs for KAS on first run.
//
// Key files are written to a configurable directory and are only generated
// if they do not already exist. This allows KAS to start up with valid
// cryptographic material without any manual key provisioning.
package keygen

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

const (
	rsaPrivateKeyFile = "kas-private.pem"
	rsaCertFile       = "kas-cert.pem"
	ecPrivateKeyFile  = "kas-ec-private.pem"
	ecCertFile        = "kas-ec-cert.pem"

	rsaKeyBits    = 2048
	certValidDays = 365 * 10 // 10 years
	certSubjectCN = "tdflite-kas"
)

// EnsureKeys checks if KAS key files exist and generates them if missing.
// It generates:
//   - RSA-2048 key pair (private key + self-signed cert)
//   - EC secp256r1 (P-256) key pair (private key + self-signed cert)
//
// Key files are:
//   - {dir}/kas-private.pem     (RSA private key)
//   - {dir}/kas-cert.pem        (RSA self-signed certificate)
//   - {dir}/kas-ec-private.pem  (EC private key)
//   - {dir}/kas-ec-cert.pem     (EC self-signed certificate)
func EnsureKeys(dir string) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("keygen: create directory %s: %w", dir, err)
	}

	rsaKeyPath := filepath.Join(dir, rsaPrivateKeyFile)
	rsaCertPath := filepath.Join(dir, rsaCertFile)
	ecKeyPath := filepath.Join(dir, ecPrivateKeyFile)
	ecCertPath := filepath.Join(dir, ecCertFile)

	// Generate RSA key pair if either file is missing.
	if !fileExists(rsaKeyPath) || !fileExists(rsaCertPath) {
		if err := generateRSAKeyPair(rsaKeyPath, rsaCertPath); err != nil {
			return fmt.Errorf("keygen: generate RSA key pair: %w", err)
		}
	}

	// Generate EC key pair if either file is missing.
	if !fileExists(ecKeyPath) || !fileExists(ecCertPath) {
		if err := generateECKeyPair(ecKeyPath, ecCertPath); err != nil {
			return fmt.Errorf("keygen: generate EC key pair: %w", err)
		}
	}

	return nil
}

// generateRSAKeyPair creates an RSA-2048 key pair and self-signed cert.
func generateRSAKeyPair(privateKeyPath, certPath string) error {
	key, err := rsa.GenerateKey(rand.Reader, rsaKeyBits)
	if err != nil {
		return fmt.Errorf("generate RSA key: %w", err)
	}

	// Marshal private key as PKCS#8.
	pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshal RSA private key: %w", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pkcs8Bytes,
	})

	if err := os.WriteFile(privateKeyPath, keyPEM, 0600); err != nil {
		return fmt.Errorf("write RSA private key: %w", err)
	}

	// Generate self-signed certificate.
	certDER, err := createSelfSignedCert(key, &key.PublicKey, x509.KeyUsageKeyEncipherment|x509.KeyUsageDigitalSignature)
	if err != nil {
		return fmt.Errorf("create RSA certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		return fmt.Errorf("write RSA certificate: %w", err)
	}

	return nil
}

// generateECKeyPair creates an EC P-256 key pair and self-signed cert.
func generateECKeyPair(privateKeyPath, certPath string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate EC key: %w", err)
	}

	// Marshal private key as PKCS#8.
	pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshal EC private key: %w", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pkcs8Bytes,
	})

	if err := os.WriteFile(privateKeyPath, keyPEM, 0600); err != nil {
		return fmt.Errorf("write EC private key: %w", err)
	}

	// Generate self-signed certificate.
	certDER, err := createSelfSignedCert(key, &key.PublicKey, x509.KeyUsageDigitalSignature)
	if err != nil {
		return fmt.Errorf("create EC certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		return fmt.Errorf("write EC certificate: %w", err)
	}

	return nil
}

// createSelfSignedCert generates a self-signed X.509 certificate DER.
func createSelfSignedCert(signingKey any, publicKey any, keyUsage x509.KeyUsage) ([]byte, error) {
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate serial number: %w", err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: certSubjectCN,
		},
		NotBefore:             now,
		NotAfter:              now.Add(time.Duration(certValidDays) * 24 * time.Hour),
		KeyUsage:              keyUsage,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, signingKey)
	if err != nil {
		return nil, fmt.Errorf("create certificate: %w", err)
	}

	return certDER, nil
}

// fileExists returns true if the file exists and is not a directory.
func fileExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !info.IsDir()
}
