package policybundle

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
)

// testSignBundle returns a minimal valid bundle with sealed data for signing tests.
func testSignBundle() *Bundle {
	return &Bundle{
		Version:   1,
		Namespace: "test.local",
		Attributes: []Attribute{
			{Name: "clearance", Rule: RuleHierarchy, Values: []string{"top-secret", "secret", "unclassified"}},
			{Name: "groups", Rule: RuleAllOf, Values: []string{"eng", "ops"}},
		},
		Identities: map[string]Identity{
			"alice": {
				Claims: map[string]interface{}{
					"clearance": "top-secret",
					"groups":    []string{"eng"},
				},
				Admin: true,
			},
			"bob": {
				Claims: map[string]interface{}{
					"clearance": "secret",
					"groups":    []string{"eng", "ops"},
				},
			},
		},
		Sealed: &Sealed{
			KASKeys:     "age-encrypted-kas-keys-placeholder",
			IDPKey:      "age-encrypted-idp-key-placeholder",
			Fingerprint: "SHA256:testfingerprint",
		},
	}
}

// writeEd25519Keys generates an Ed25519 keypair and writes the private key
// (OpenSSH PEM) and public key (authorized_keys format) to temporary files.
// Returns paths to (privKeyFile, pubKeyFile).
func writeEd25519Keys(t *testing.T) (string, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating ed25519 key: %v", err)
	}

	dir := t.TempDir()

	// Private key in OpenSSH PEM format.
	privPEM, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatalf("marshaling private key: %v", err)
	}
	privPath := filepath.Join(dir, "id_ed25519")
	if err := os.WriteFile(privPath, pem.EncodeToMemory(privPEM), 0600); err != nil {
		t.Fatalf("writing private key: %v", err)
	}

	// Public key in authorized_keys format.
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("creating ssh public key: %v", err)
	}
	pubPath := filepath.Join(dir, "id_ed25519.pub")
	if err := os.WriteFile(pubPath, ssh.MarshalAuthorizedKey(sshPub), 0644); err != nil {
		t.Fatalf("writing public key: %v", err)
	}

	return privPath, pubPath
}

// writeRSAKeys generates an RSA keypair and writes them in SSH format.
func writeRSAKeys(t *testing.T) (string, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating RSA key: %v", err)
	}

	dir := t.TempDir()

	privPEM, err := ssh.MarshalPrivateKey(key, "")
	if err != nil {
		t.Fatalf("marshaling RSA private key: %v", err)
	}
	privPath := filepath.Join(dir, "id_rsa")
	if err := os.WriteFile(privPath, pem.EncodeToMemory(privPEM), 0600); err != nil {
		t.Fatalf("writing RSA private key: %v", err)
	}

	sshPub, err := ssh.NewPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("creating RSA ssh public key: %v", err)
	}
	pubPath := filepath.Join(dir, "id_rsa.pub")
	if err := os.WriteFile(pubPath, ssh.MarshalAuthorizedKey(sshPub), 0644); err != nil {
		t.Fatalf("writing RSA public key: %v", err)
	}

	return privPath, pubPath
}

// writeECDSAKeys generates an ECDSA P-256 keypair and writes them in SSH format.
func writeECDSAKeys(t *testing.T) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating ECDSA key: %v", err)
	}

	dir := t.TempDir()

	privPEM, err := ssh.MarshalPrivateKey(key, "")
	if err != nil {
		t.Fatalf("marshaling ECDSA private key: %v", err)
	}
	privPath := filepath.Join(dir, "id_ecdsa")
	if err := os.WriteFile(privPath, pem.EncodeToMemory(privPEM), 0600); err != nil {
		t.Fatalf("writing ECDSA private key: %v", err)
	}

	sshPub, err := ssh.NewPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("creating ECDSA ssh public key: %v", err)
	}
	pubPath := filepath.Join(dir, "id_ecdsa.pub")
	if err := os.WriteFile(pubPath, ssh.MarshalAuthorizedKey(sshPub), 0644); err != nil {
		t.Fatalf("writing ECDSA public key: %v", err)
	}

	return privPath, pubPath
}

// ---------------------------------------------------------------------------
// Ed25519 sign and verify
// ---------------------------------------------------------------------------

func TestSignVerifyEd25519(t *testing.T) {
	privPath, pubPath := writeEd25519Keys(t)
	b := testSignBundle()

	if err := SignBundle(b, privPath); err != nil {
		t.Fatalf("SignBundle: %v", err)
	}
	if b.Signature == "" {
		t.Fatal("Signature should be non-empty after signing")
	}

	if err := VerifySignature(b, pubPath); err != nil {
		t.Fatalf("VerifySignature: %v", err)
	}
}

// ---------------------------------------------------------------------------
// RSA sign and verify
// ---------------------------------------------------------------------------

func TestSignVerifyRSA(t *testing.T) {
	privPath, pubPath := writeRSAKeys(t)
	b := testSignBundle()

	if err := SignBundle(b, privPath); err != nil {
		t.Fatalf("SignBundle: %v", err)
	}
	if b.Signature == "" {
		t.Fatal("Signature should be non-empty after signing")
	}

	if err := VerifySignature(b, pubPath); err != nil {
		t.Fatalf("VerifySignature: %v", err)
	}
}

// ---------------------------------------------------------------------------
// ECDSA sign and verify (bonus — validates the third key type)
// ---------------------------------------------------------------------------

func TestSignVerifyECDSA(t *testing.T) {
	privPath, pubPath := writeECDSAKeys(t)
	b := testSignBundle()

	if err := SignBundle(b, privPath); err != nil {
		t.Fatalf("SignBundle: %v", err)
	}
	if b.Signature == "" {
		t.Fatal("Signature should be non-empty after signing")
	}

	if err := VerifySignature(b, pubPath); err != nil {
		t.Fatalf("VerifySignature: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Tampered bundle fails verification
// ---------------------------------------------------------------------------

func TestVerifyTampered(t *testing.T) {
	privPath, pubPath := writeEd25519Keys(t)
	b := testSignBundle()

	if err := SignBundle(b, privPath); err != nil {
		t.Fatalf("SignBundle: %v", err)
	}

	// Tamper with an attribute value.
	b.Attributes[0].Values[0] = "TAMPERED"

	if err := VerifySignature(b, pubPath); err == nil {
		t.Fatal("expected verification to fail on tampered bundle, got nil")
	}
}

// ---------------------------------------------------------------------------
// Wrong key fails verification
// ---------------------------------------------------------------------------

func TestVerifyWrongKey(t *testing.T) {
	privPath, _ := writeEd25519Keys(t)
	_, pubPath2 := writeEd25519Keys(t) // different key pair

	b := testSignBundle()

	if err := SignBundle(b, privPath); err != nil {
		t.Fatalf("SignBundle: %v", err)
	}

	if err := VerifySignature(b, pubPath2); err == nil {
		t.Fatal("expected verification to fail with wrong key, got nil")
	}
}

// ---------------------------------------------------------------------------
// Passphrase mode sign and verify
// ---------------------------------------------------------------------------

func TestPassphraseSignVerify(t *testing.T) {
	b := testSignBundle()

	if err := SignBundlePassphrase(b); err != nil {
		t.Fatalf("SignBundlePassphrase: %v", err)
	}
	if b.Signature == "" {
		t.Fatal("Signature should be non-empty after passphrase signing")
	}

	if err := VerifyPassphraseSignature(b); err != nil {
		t.Fatalf("VerifyPassphraseSignature: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Passphrase mode: tampered bundle fails verification
// ---------------------------------------------------------------------------

func TestPassphraseSignVerifyTampered(t *testing.T) {
	b := testSignBundle()

	if err := SignBundlePassphrase(b); err != nil {
		t.Fatalf("SignBundlePassphrase: %v", err)
	}

	// Tamper with an attribute value.
	b.Attributes[0].Values[0] = "TAMPERED"

	if err := VerifyPassphraseSignature(b); err == nil {
		t.Fatal("expected passphrase verification to fail on tampered bundle, got nil")
	}
}

// ---------------------------------------------------------------------------
// canonicalBytes stability: same bundle produces same bytes
// ---------------------------------------------------------------------------

func TestCanonicalBytesStable(t *testing.T) {
	b := testSignBundle()
	b.Signature = "should-be-cleared"

	b1, err := canonicalBytes(b)
	if err != nil {
		t.Fatalf("canonicalBytes (1st call): %v", err)
	}
	b2, err := canonicalBytes(b)
	if err != nil {
		t.Fatalf("canonicalBytes (2nd call): %v", err)
	}

	if !bytes.Equal(b1, b2) {
		t.Fatalf("canonicalBytes produced different results:\n  first:  %s\n  second: %s", b1, b2)
	}

	// Verify the original bundle's Signature was not mutated.
	if b.Signature != "should-be-cleared" {
		t.Errorf("canonicalBytes mutated the original bundle's Signature to %q", b.Signature)
	}
}
