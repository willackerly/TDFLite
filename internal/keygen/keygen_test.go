package keygen

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestEnsureKeysCreatesAllFiles(t *testing.T) {
	dir := t.TempDir()

	if err := EnsureKeys(dir); err != nil {
		t.Fatalf("EnsureKeys() error = %v", err)
	}

	expectedFiles := []string{
		rsaPrivateKeyFile,
		rsaCertFile,
		ecPrivateKeyFile,
		ecCertFile,
	}

	for _, name := range expectedFiles {
		path := filepath.Join(dir, name)
		info, err := os.Stat(path)
		if err != nil {
			t.Errorf("expected file %s to exist: %v", name, err)
			continue
		}
		if info.IsDir() {
			t.Errorf("expected %s to be a file, not a directory", name)
		}
		if info.Size() == 0 {
			t.Errorf("expected %s to be non-empty", name)
		}
	}
}

func TestRSAPrivateKeyIsValidPEM(t *testing.T) {
	dir := t.TempDir()

	if err := EnsureKeys(dir); err != nil {
		t.Fatalf("EnsureKeys() error = %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, rsaPrivateKeyFile))
	if err != nil {
		t.Fatalf("read RSA private key: %v", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("RSA private key is not valid PEM")
	}
	if block.Type != "PRIVATE KEY" {
		t.Errorf("RSA private key PEM type = %q, want %q", block.Type, "PRIVATE KEY")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse RSA PKCS#8 private key: %v", err)
	}

	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("parsed key is %T, want *rsa.PrivateKey", key)
	}
	if rsaKey.N.BitLen() != 2048 {
		t.Errorf("RSA key size = %d bits, want 2048", rsaKey.N.BitLen())
	}
}

func TestECPrivateKeyIsValidPEM(t *testing.T) {
	dir := t.TempDir()

	if err := EnsureKeys(dir); err != nil {
		t.Fatalf("EnsureKeys() error = %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, ecPrivateKeyFile))
	if err != nil {
		t.Fatalf("read EC private key: %v", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("EC private key is not valid PEM")
	}
	if block.Type != "PRIVATE KEY" {
		t.Errorf("EC private key PEM type = %q, want %q", block.Type, "PRIVATE KEY")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse EC PKCS#8 private key: %v", err)
	}

	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("parsed key is %T, want *ecdsa.PrivateKey", key)
	}
	if ecKey.Curve != elliptic.P256() {
		t.Errorf("EC curve = %v, want P-256", ecKey.Curve.Params().Name)
	}
}

func TestRSACertificateIsValidX509(t *testing.T) {
	dir := t.TempDir()

	if err := EnsureKeys(dir); err != nil {
		t.Fatalf("EnsureKeys() error = %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, rsaCertFile))
	if err != nil {
		t.Fatalf("read RSA cert: %v", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("RSA cert is not valid PEM")
	}
	if block.Type != "CERTIFICATE" {
		t.Errorf("RSA cert PEM type = %q, want %q", block.Type, "CERTIFICATE")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse RSA certificate: %v", err)
	}

	if cert.Subject.CommonName != certSubjectCN {
		t.Errorf("RSA cert subject CN = %q, want %q", cert.Subject.CommonName, certSubjectCN)
	}

	if cert.KeyUsage&x509.KeyUsageKeyEncipherment == 0 {
		t.Error("RSA cert missing KeyEncipherment usage")
	}
	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Error("RSA cert missing DigitalSignature usage")
	}
}

func TestECCertificateIsValidX509(t *testing.T) {
	dir := t.TempDir()

	if err := EnsureKeys(dir); err != nil {
		t.Fatalf("EnsureKeys() error = %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, ecCertFile))
	if err != nil {
		t.Fatalf("read EC cert: %v", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("EC cert is not valid PEM")
	}
	if block.Type != "CERTIFICATE" {
		t.Errorf("EC cert PEM type = %q, want %q", block.Type, "CERTIFICATE")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse EC certificate: %v", err)
	}

	if cert.Subject.CommonName != certSubjectCN {
		t.Errorf("EC cert subject CN = %q, want %q", cert.Subject.CommonName, certSubjectCN)
	}

	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Error("EC cert missing DigitalSignature usage")
	}
}

func TestEnsureKeysIsIdempotent(t *testing.T) {
	dir := t.TempDir()

	// First call: generate keys.
	if err := EnsureKeys(dir); err != nil {
		t.Fatalf("EnsureKeys() first call error = %v", err)
	}

	// Record modification times of all files.
	files := []string{rsaPrivateKeyFile, rsaCertFile, ecPrivateKeyFile, ecCertFile}
	modTimes := make(map[string]int64, len(files))
	contents := make(map[string][]byte, len(files))
	for _, name := range files {
		path := filepath.Join(dir, name)
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat %s: %v", name, err)
		}
		modTimes[name] = info.ModTime().UnixNano()
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		contents[name] = data
	}

	// Second call: should not regenerate.
	if err := EnsureKeys(dir); err != nil {
		t.Fatalf("EnsureKeys() second call error = %v", err)
	}

	// Verify files were not modified.
	for _, name := range files {
		path := filepath.Join(dir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s after second call: %v", name, err)
		}
		if string(data) != string(contents[name]) {
			t.Errorf("file %s was modified on second EnsureKeys() call", name)
		}
	}
}

func TestRSAKeyIs2048Bits(t *testing.T) {
	dir := t.TempDir()

	if err := EnsureKeys(dir); err != nil {
		t.Fatalf("EnsureKeys() error = %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, rsaPrivateKeyFile))
	if err != nil {
		t.Fatalf("read RSA private key: %v", err)
	}

	block, _ := pem.Decode(data)
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse RSA key: %v", err)
	}

	rsaKey := key.(*rsa.PrivateKey)
	if rsaKey.N.BitLen() != 2048 {
		t.Errorf("RSA key size = %d bits, want 2048", rsaKey.N.BitLen())
	}
}

func TestECKeyIsP256(t *testing.T) {
	dir := t.TempDir()

	if err := EnsureKeys(dir); err != nil {
		t.Fatalf("EnsureKeys() error = %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, ecPrivateKeyFile))
	if err != nil {
		t.Fatalf("read EC private key: %v", err)
	}

	block, _ := pem.Decode(data)
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse EC key: %v", err)
	}

	ecKey := key.(*ecdsa.PrivateKey)
	if ecKey.Curve != elliptic.P256() {
		t.Errorf("EC curve = %v, want P-256", ecKey.Curve.Params().Name)
	}
}

func TestEnsureKeysCreatesDirectory(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "subdir", "keys")

	if err := EnsureKeys(dir); err != nil {
		t.Fatalf("EnsureKeys() error = %v", err)
	}

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("directory %s was not created: %v", dir, err)
	}
	if !info.IsDir() {
		t.Errorf("%s is not a directory", dir)
	}
}

func TestPrivateKeyFilePermissions(t *testing.T) {
	dir := t.TempDir()

	if err := EnsureKeys(dir); err != nil {
		t.Fatalf("EnsureKeys() error = %v", err)
	}

	for _, name := range []string{rsaPrivateKeyFile, ecPrivateKeyFile} {
		path := filepath.Join(dir, name)
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat %s: %v", name, err)
		}
		perm := info.Mode().Perm()
		if perm != 0600 {
			t.Errorf("%s permissions = %o, want 0600", name, perm)
		}
	}
}

func TestCertFilePermissions(t *testing.T) {
	dir := t.TempDir()

	if err := EnsureKeys(dir); err != nil {
		t.Fatalf("EnsureKeys() error = %v", err)
	}

	for _, name := range []string{rsaCertFile, ecCertFile} {
		path := filepath.Join(dir, name)
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat %s: %v", name, err)
		}
		perm := info.Mode().Perm()
		if perm != 0644 {
			t.Errorf("%s permissions = %o, want 0644", name, perm)
		}
	}
}
