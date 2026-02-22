package policybundle

import (
	"crypto"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
)

func init() {
	// Use a low work factor for fast tests.
	sealWorkFactor = 10
}

// testBundle creates a minimal valid bundle for testing.
func testBundle() *Bundle {
	return &Bundle{
		Version:   1,
		Namespace: "test.local",
		Attributes: []Attribute{
			{Name: "level", Rule: RuleHierarchy, Values: []string{"top", "secret", "public"}},
		},
		Identities: map[string]Identity{
			"alice": {Claims: map[string]interface{}{"level": "top"}},
		},
	}
}

// writeSSHKeyPair generates an Ed25519 SSH keypair and writes it to temp files.
// Returns (pubKeyPath, privKeyPath, cleanup).
func writeSSHKeyPair(t *testing.T) (string, string) {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating ed25519 key: %v", err)
	}

	// Marshal private key to OpenSSH format.
	privPEM, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatalf("marshaling private key: %v", err)
	}

	privPath := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(privPath, pem.EncodeToMemory(privPEM), 0600); err != nil {
		t.Fatalf("writing private key: %v", err)
	}

	// Marshal public key to authorized_keys format.
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("creating SSH public key: %v", err)
	}
	pubBytes := ssh.MarshalAuthorizedKey(sshPub)

	pubPath := filepath.Join(t.TempDir(), "id_ed25519.pub")
	if err := os.WriteFile(pubPath, pubBytes, 0644); err != nil {
		t.Fatalf("writing public key: %v", err)
	}

	return pubPath, privPath
}

func TestSealUnsealSSHKey(t *testing.T) {
	pubPath, privPath := writeSSHKeyPair(t)
	bundle := testBundle()

	// Seal the bundle.
	if err := SealWithSSHKey(bundle, pubPath); err != nil {
		t.Fatalf("SealWithSSHKey: %v", err)
	}

	if bundle.Sealed == nil {
		t.Fatal("bundle.Sealed is nil after sealing")
	}
	if bundle.Sealed.KASKeys == "" {
		t.Fatal("sealed KAS keys are empty")
	}
	if bundle.Sealed.IDPKey == "" {
		t.Fatal("sealed IdP key is empty")
	}

	// Unseal the bundle.
	keys, err := UnsealWithSSHKey(bundle, privPath)
	if err != nil {
		t.Fatalf("UnsealWithSSHKey: %v", err)
	}

	// Verify RSA key.
	if keys.RSAPrivate == nil {
		t.Fatal("RSA private key is nil")
	}
	if err := keys.RSAPrivate.Validate(); err != nil {
		t.Fatalf("RSA key validation failed: %v", err)
	}
	if keys.RSAPrivate.N.BitLen() < 2048 {
		t.Fatalf("RSA key too small: %d bits", keys.RSAPrivate.N.BitLen())
	}

	// Verify EC key.
	if keys.ECPrivate == nil {
		t.Fatal("EC private key is nil")
	}
	if keys.ECPrivate.Curve != elliptic.P256() {
		t.Fatal("EC key is not P-256")
	}

	// Verify certs are present and parseable.
	if len(keys.RSACert) == 0 {
		t.Fatal("RSA cert is empty")
	}
	rsaBlock, _ := pem.Decode(keys.RSACert)
	if rsaBlock == nil || rsaBlock.Type != "CERTIFICATE" {
		t.Fatal("RSA cert is not a valid PEM CERTIFICATE block")
	}

	if len(keys.ECCert) == 0 {
		t.Fatal("EC cert is empty")
	}
	ecBlock, _ := pem.Decode(keys.ECCert)
	if ecBlock == nil || ecBlock.Type != "CERTIFICATE" {
		t.Fatal("EC cert is not a valid PEM CERTIFICATE block")
	}

	// Verify IdP key.
	if keys.IDPKey == nil {
		t.Fatal("IdP key is nil")
	}
	if err := keys.IDPKey.Validate(); err != nil {
		t.Fatalf("IdP key validation failed: %v", err)
	}

	// Verify RSA key can sign and verify.
	testData := []byte("test data for signing")
	digest := sha256.Sum256(testData)
	sig, err := keys.RSAPrivate.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("RSA signing failed: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("RSA signature is empty")
	}

	// Verify EC key can sign and verify.
	ecSig, err := keys.ECPrivate.Sign(rand.Reader, digest[:], nil)
	if err != nil {
		t.Fatalf("EC signing failed: %v", err)
	}
	if len(ecSig) == 0 {
		t.Fatal("EC signature is empty")
	}
}

func TestSealUnsealPassphrase(t *testing.T) {
	bundle := testBundle()
	passphrase := "test-passphrase-42"

	// Seal the bundle.
	if err := SealWithPassphrase(bundle, passphrase); err != nil {
		t.Fatalf("SealWithPassphrase: %v", err)
	}

	if bundle.Sealed == nil {
		t.Fatal("bundle.Sealed is nil after sealing")
	}

	// Unseal the bundle.
	keys, err := UnsealWithPassphrase(bundle, passphrase)
	if err != nil {
		t.Fatalf("UnsealWithPassphrase: %v", err)
	}

	// Verify keys.
	if keys.RSAPrivate == nil {
		t.Fatal("RSA private key is nil")
	}
	if err := keys.RSAPrivate.Validate(); err != nil {
		t.Fatalf("RSA key validation failed: %v", err)
	}

	if keys.ECPrivate == nil {
		t.Fatal("EC private key is nil")
	}
	if keys.ECPrivate.Curve != elliptic.P256() {
		t.Fatal("EC key is not P-256")
	}

	if keys.IDPKey == nil {
		t.Fatal("IdP key is nil")
	}
	if err := keys.IDPKey.Validate(); err != nil {
		t.Fatalf("IdP key validation failed: %v", err)
	}

	// Verify certs.
	if len(keys.RSACert) == 0 {
		t.Fatal("RSA cert is empty")
	}
	if len(keys.ECCert) == 0 {
		t.Fatal("EC cert is empty")
	}
}

func TestUnsealWrongSSHKey(t *testing.T) {
	pubPath1, _ := writeSSHKeyPair(t)
	_, privPath2 := writeSSHKeyPair(t)

	bundle := testBundle()

	// Seal with key 1.
	if err := SealWithSSHKey(bundle, pubPath1); err != nil {
		t.Fatalf("SealWithSSHKey: %v", err)
	}

	// Try to unseal with key 2 -- should fail.
	_, err := UnsealWithSSHKey(bundle, privPath2)
	if err == nil {
		t.Fatal("expected error when unsealing with wrong SSH key, got nil")
	}
}

func TestUnsealWrongPassphrase(t *testing.T) {
	bundle := testBundle()

	if err := SealWithPassphrase(bundle, "correct-passphrase"); err != nil {
		t.Fatalf("SealWithPassphrase: %v", err)
	}

	_, err := UnsealWithPassphrase(bundle, "wrong-passphrase")
	if err == nil {
		t.Fatal("expected error when unsealing with wrong passphrase, got nil")
	}
}

func TestSealedBundleHasFingerprint(t *testing.T) {
	pubPath, _ := writeSSHKeyPair(t)
	bundle := testBundle()

	if err := SealWithSSHKey(bundle, pubPath); err != nil {
		t.Fatalf("SealWithSSHKey: %v", err)
	}

	if bundle.Sealed.Fingerprint == "" {
		t.Fatal("fingerprint is empty after SSH seal")
	}

	if bundle.Sealed.Fingerprint[:7] != "SHA256:" {
		t.Fatalf("fingerprint does not start with SHA256:, got %q", bundle.Sealed.Fingerprint)
	}
}

func TestPassphraseSealHasNoFingerprint(t *testing.T) {
	bundle := testBundle()

	if err := SealWithPassphrase(bundle, "some-passphrase"); err != nil {
		t.Fatalf("SealWithPassphrase: %v", err)
	}

	if bundle.Sealed.Fingerprint != "" {
		t.Fatalf("expected empty fingerprint for passphrase seal, got %q", bundle.Sealed.Fingerprint)
	}

	if bundle.Sealed.Method != "passphrase" {
		t.Fatalf("expected method 'passphrase', got %q", bundle.Sealed.Method)
	}
}
