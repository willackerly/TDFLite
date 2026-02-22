package tests_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/willackerly/TDFLite/internal/policybundle"
	"github.com/willackerly/TDFLite/internal/policybundle/templates"
	"golang.org/x/crypto/ssh"
)

// ---------------------------------------------------------------------------
// SSH Key Generation Tests
// ---------------------------------------------------------------------------

// TestUpSSHKeyGeneration verifies that Ed25519 SSH keypair generation works
// correctly, mirroring the logic in main.go's generateSSHKeyPair.
func TestUpSSHKeyGeneration(t *testing.T) {
	t.Run("GeneratesValidEd25519Keypair", func(t *testing.T) {
		dir := t.TempDir()
		privPath := filepath.Join(dir, "id_ed25519")
		pubPath := filepath.Join(dir, "id_ed25519.pub")

		// Generate keypair using the same logic as main.go:generateSSHKeyPair.
		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("generating ed25519 key: %v", err)
		}

		privPEM, err := ssh.MarshalPrivateKey(privKey, "")
		if err != nil {
			t.Fatalf("marshaling private key: %v", err)
		}
		if err := os.WriteFile(privPath, pem.EncodeToMemory(privPEM), 0600); err != nil {
			t.Fatalf("writing private key: %v", err)
		}

		sshPub, err := ssh.NewPublicKey(pubKey)
		if err != nil {
			t.Fatalf("creating SSH public key: %v", err)
		}
		if err := os.WriteFile(pubPath, ssh.MarshalAuthorizedKey(sshPub), 0644); err != nil {
			t.Fatalf("writing public key: %v", err)
		}

		// Read back and verify private key is parseable.
		privData, err := os.ReadFile(privPath)
		if err != nil {
			t.Fatalf("reading private key: %v", err)
		}
		rawKey, err := ssh.ParseRawPrivateKey(privData)
		if err != nil {
			t.Fatalf("parsing private key: %v", err)
		}
		parsedPriv, ok := rawKey.(*ed25519.PrivateKey)
		if !ok {
			t.Fatalf("expected *ed25519.PrivateKey, got %T", rawKey)
		}
		if len(*parsedPriv) != ed25519.PrivateKeySize {
			t.Fatalf("private key wrong size: got %d, want %d", len(*parsedPriv), ed25519.PrivateKeySize)
		}

		// Read back and verify public key is parseable.
		pubData, err := os.ReadFile(pubPath)
		if err != nil {
			t.Fatalf("reading public key: %v", err)
		}
		parsedSSHPub, _, _, _, err := ssh.ParseAuthorizedKey(pubData)
		if err != nil {
			t.Fatalf("parsing public key: %v", err)
		}
		if parsedSSHPub.Type() != "ssh-ed25519" {
			t.Fatalf("expected ssh-ed25519 key type, got %q", parsedSSHPub.Type())
		}
	})

	t.Run("PrivateKeyCanSealAndUnsealBundle", func(t *testing.T) {
		pubPath, privPath := generateSSHKeyPair(t)

		// Load a template to get a real bundle.
		bundle, err := templates.Load("healthcare")
		if err != nil {
			t.Fatalf("loading template: %v", err)
		}

		// Seal with the generated public key.
		if err := policybundle.SealWithSSHKey(bundle, pubPath); err != nil {
			t.Fatalf("SealWithSSHKey: %v", err)
		}
		if err := policybundle.SignBundle(bundle, privPath); err != nil {
			t.Fatalf("SignBundle: %v", err)
		}

		// Unseal with the generated private key.
		keys, err := policybundle.UnsealWithSSHKey(bundle, privPath)
		if err != nil {
			t.Fatalf("UnsealWithSSHKey: %v", err)
		}

		// Verify extracted keys are valid.
		if keys.RSAPrivate == nil {
			t.Fatal("RSAPrivate is nil after unseal")
		}
		if keys.ECPrivate == nil {
			t.Fatal("ECPrivate is nil after unseal")
		}
		if keys.IDPKey == nil {
			t.Fatal("IDPKey is nil after unseal")
		}
	})

	t.Run("PublicKeyFingerprintFormat", func(t *testing.T) {
		dir := t.TempDir()
		pubKey, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("generating key: %v", err)
		}

		sshPub, err := ssh.NewPublicKey(pubKey)
		if err != nil {
			t.Fatalf("creating SSH public key: %v", err)
		}

		pubPath := filepath.Join(dir, "id_ed25519.pub")
		if err := os.WriteFile(pubPath, ssh.MarshalAuthorizedKey(sshPub), 0644); err != nil {
			t.Fatalf("writing public key: %v", err)
		}

		// Compute fingerprint the same way SealWithSSHKey does.
		fingerprint := ssh.FingerprintSHA256(sshPub)

		if !strings.HasPrefix(fingerprint, "SHA256:") {
			t.Fatalf("fingerprint should start with 'SHA256:', got %q", fingerprint)
		}
		// SHA256 base64 encoded is 43 chars + "SHA256:" prefix = 50 chars.
		if len(fingerprint) < 50 {
			t.Fatalf("fingerprint too short: %q (len=%d)", fingerprint, len(fingerprint))
		}
	})

	t.Run("KeypairCreatesParentDirectory", func(t *testing.T) {
		dir := t.TempDir()
		nestedDir := filepath.Join(dir, "deep", "nested", ".ssh")
		privPath := filepath.Join(nestedDir, "id_ed25519")
		pubPath := filepath.Join(nestedDir, "id_ed25519.pub")

		// Replicate the directory creation logic from generateSSHKeyPair.
		if err := os.MkdirAll(filepath.Dir(privPath), 0700); err != nil {
			t.Fatalf("creating directory: %v", err)
		}

		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("generating key: %v", err)
		}

		privPEM, err := ssh.MarshalPrivateKey(privKey, "")
		if err != nil {
			t.Fatalf("marshaling private key: %v", err)
		}
		if err := os.WriteFile(privPath, pem.EncodeToMemory(privPEM), 0600); err != nil {
			t.Fatalf("writing private key: %v", err)
		}

		sshPub, err := ssh.NewPublicKey(pubKey)
		if err != nil {
			t.Fatalf("creating SSH public key: %v", err)
		}
		if err := os.WriteFile(pubPath, ssh.MarshalAuthorizedKey(sshPub), 0644); err != nil {
			t.Fatalf("writing public key: %v", err)
		}

		// Verify both files exist.
		if _, err := os.Stat(privPath); err != nil {
			t.Fatalf("private key not created: %v", err)
		}
		if _, err := os.Stat(pubPath); err != nil {
			t.Fatalf("public key not created: %v", err)
		}

		// Verify directory permissions.
		info, err := os.Stat(nestedDir)
		if err != nil {
			t.Fatalf("stat nested dir: %v", err)
		}
		if info.Mode().Perm() != 0700 {
			t.Fatalf("expected 0700 permissions on SSH dir, got %o", info.Mode().Perm())
		}
	})
}

// ---------------------------------------------------------------------------
// Template -> Seal -> Verify Flow Tests
// ---------------------------------------------------------------------------

// TestUpTemplateSealVerifyFlow tests the complete `up` flow for each template:
// generate keypair, load template, seal, sign, verify, unseal, validate keys.
func TestUpTemplateSealVerifyFlow(t *testing.T) {
	templateNames := templates.Available()
	if len(templateNames) == 0 {
		t.Fatal("no templates available")
	}

	for _, tmplName := range templateNames {
		tmplName := tmplName // capture range variable
		t.Run(tmplName, func(t *testing.T) {
			t.Parallel()

			// Step 1: Generate SSH keypair in temp dir.
			pubPath, privPath := generateSSHKeyPair(t)

			// Step 2: Load template.
			bundle, err := templates.Load(tmplName)
			if err != nil {
				t.Fatalf("templates.Load(%q): %v", tmplName, err)
			}

			// Verify template has content.
			if len(bundle.Attributes) == 0 {
				t.Fatal("template has no attributes")
			}
			if len(bundle.Identities) == 0 {
				t.Fatal("template has no identities")
			}

			// Step 3: Seal with SSH key.
			if err := policybundle.SealWithSSHKey(bundle, pubPath); err != nil {
				t.Fatalf("SealWithSSHKey: %v", err)
			}

			// Step 4: Sign with SSH private key.
			if err := policybundle.SignBundle(bundle, privPath); err != nil {
				t.Fatalf("SignBundle: %v", err)
			}

			// Step 5: Verify signature.
			if err := policybundle.VerifySignature(bundle, pubPath); err != nil {
				t.Fatalf("VerifySignature: %v", err)
			}

			// Step 6: Unseal with SSH private key.
			keys, err := policybundle.UnsealWithSSHKey(bundle, privPath)
			if err != nil {
				t.Fatalf("UnsealWithSSHKey: %v", err)
			}

			// Step 7: Verify KAS keys are present and valid.
			if keys.RSAPrivate == nil {
				t.Fatal("RSAPrivate is nil")
			}
			if err := keys.RSAPrivate.Validate(); err != nil {
				t.Fatalf("RSA key validation failed: %v", err)
			}
			if keys.RSAPrivate.N.BitLen() < 2048 {
				t.Fatalf("RSA key too small: %d bits", keys.RSAPrivate.N.BitLen())
			}

			if keys.ECPrivate == nil {
				t.Fatal("ECPrivate is nil")
			}
			if keys.ECPrivate.Curve.Params().BitSize != 256 {
				t.Fatalf("EC key wrong curve: expected P-256 (256 bits), got %d bits",
					keys.ECPrivate.Curve.Params().BitSize)
			}

			if keys.IDPKey == nil {
				t.Fatal("IDPKey is nil")
			}
			if err := keys.IDPKey.Validate(); err != nil {
				t.Fatalf("IDP key validation failed: %v", err)
			}

			// Verify RSA certificate is valid PEM.
			rsaBlock, _ := pem.Decode(keys.RSACert)
			if rsaBlock == nil || rsaBlock.Type != "CERTIFICATE" {
				t.Fatal("RSACert is not a valid PEM CERTIFICATE")
			}
			rsaCert, err := x509.ParseCertificate(rsaBlock.Bytes)
			if err != nil {
				t.Fatalf("parsing RSA cert: %v", err)
			}
			// Verify the cert's public key matches the private key.
			certRSAPub, ok := rsaCert.PublicKey.(*rsa.PublicKey)
			if !ok {
				t.Fatal("RSA cert public key is not *rsa.PublicKey")
			}
			if certRSAPub.N.Cmp(keys.RSAPrivate.N) != 0 {
				t.Fatal("RSA cert public key does not match private key")
			}

			// Verify EC certificate is valid PEM.
			ecBlock, _ := pem.Decode(keys.ECCert)
			if ecBlock == nil || ecBlock.Type != "CERTIFICATE" {
				t.Fatal("ECCert is not a valid PEM CERTIFICATE")
			}
			ecCert, err := x509.ParseCertificate(ecBlock.Bytes)
			if err != nil {
				t.Fatalf("parsing EC cert: %v", err)
			}
			certECPub, ok := ecCert.PublicKey.(*ecdsa.PublicKey)
			if !ok {
				t.Fatal("EC cert public key is not *ecdsa.PublicKey")
			}
			if certECPub.X.Cmp(keys.ECPrivate.X) != 0 || certECPub.Y.Cmp(keys.ECPrivate.Y) != 0 {
				t.Fatal("EC cert public key does not match private key")
			}

			// Step 8: Write sealed bundle to temp file, read it back, verify round-trip.
			tmpDir := t.TempDir()
			sealedPath := filepath.Join(tmpDir, "policy.sealed.json")

			data, err := json.MarshalIndent(bundle, "", "  ")
			if err != nil {
				t.Fatalf("marshaling sealed bundle: %v", err)
			}
			if err := os.WriteFile(sealedPath, append(data, '\n'), 0600); err != nil {
				t.Fatalf("writing sealed bundle: %v", err)
			}

			// Read it back.
			readData, err := os.ReadFile(sealedPath)
			if err != nil {
				t.Fatalf("reading sealed bundle: %v", err)
			}

			var loaded policybundle.Bundle
			if err := json.Unmarshal(readData, &loaded); err != nil {
				t.Fatalf("unmarshaling round-tripped bundle: %v", err)
			}

			// Verify the round-tripped bundle is sealed.
			if !loaded.IsSealed() {
				t.Fatal("round-tripped bundle is not sealed")
			}

			// Verify signature still valid on round-tripped bundle.
			if err := policybundle.VerifySignature(&loaded, pubPath); err != nil {
				t.Fatalf("VerifySignature on round-tripped bundle: %v", err)
			}

			// Verify unseal still works on round-tripped bundle.
			rtKeys, err := policybundle.UnsealWithSSHKey(&loaded, privPath)
			if err != nil {
				t.Fatalf("UnsealWithSSHKey on round-tripped bundle: %v", err)
			}
			if rtKeys.RSAPrivate == nil || rtKeys.ECPrivate == nil || rtKeys.IDPKey == nil {
				t.Fatal("round-tripped unseal produced nil keys")
			}

			// Verify attribute count preserved.
			if len(loaded.Attributes) != len(bundle.Attributes) {
				t.Fatalf("attribute count mismatch: original=%d, round-tripped=%d",
					len(bundle.Attributes), len(loaded.Attributes))
			}

			// Verify identity count preserved.
			if len(loaded.Identities) != len(bundle.Identities) {
				t.Fatalf("identity count mismatch: original=%d, round-tripped=%d",
					len(bundle.Identities), len(loaded.Identities))
			}

			// Verify fingerprint is present and in SHA256 format.
			if loaded.Sealed.Fingerprint == "" {
				t.Fatal("sealed fingerprint is empty")
			}
			if !strings.HasPrefix(loaded.Sealed.Fingerprint, "SHA256:") {
				t.Fatalf("fingerprint format unexpected: %q", loaded.Sealed.Fingerprint)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Non-Interactive Mode / loadTemplateOrFile Logic Tests
// ---------------------------------------------------------------------------

// TestUpLoadTemplateOrFile tests the template-or-file loading logic that
// underpins --template flag handling.
func TestUpLoadTemplateOrFile(t *testing.T) {
	t.Run("KnownTemplateNames", func(t *testing.T) {
		for _, name := range templates.Available() {
			bundle, err := templates.Load(name)
			if err != nil {
				t.Errorf("templates.Load(%q): %v", name, err)
				continue
			}
			if len(bundle.Attributes) == 0 {
				t.Errorf("template %q has no attributes", name)
			}
			if len(bundle.Identities) == 0 {
				t.Errorf("template %q has no identities", name)
			}
		}
	})

	t.Run("CaseInsensitiveTemplateNames", func(t *testing.T) {
		// The loadTemplateOrFile function uses strings.EqualFold for matching.
		// We replicate that logic here since loadTemplateOrFile is unexported.
		testCases := []struct {
			input    string
			expected string // the lowercase canonical name
		}{
			{"Healthcare", "healthcare"},
			{"HEALTHCARE", "healthcare"},
			{"healthcare", "healthcare"},
			{"Finance", "finance"},
			{"FINANCE", "finance"},
			{"Defense", "defense"},
			{"DEFENSE", "defense"},
			{"dEfEnSe", "defense"},
		}

		for _, tc := range testCases {
			// Replicate loadTemplateOrFile's case-insensitive lookup.
			var found string
			for _, available := range templates.Available() {
				if strings.EqualFold(tc.input, available) {
					found = available
					break
				}
			}
			if found != tc.expected {
				t.Errorf("input %q: expected to match template %q, got %q", tc.input, tc.expected, found)
			}

			// Also verify the matched name can actually load.
			if found != "" {
				bundle, err := templates.Load(found)
				if err != nil {
					t.Errorf("templates.Load(%q): %v", found, err)
					continue
				}
				if bundle == nil {
					t.Errorf("templates.Load(%q) returned nil bundle", found)
				}
			}
		}
	})

	t.Run("FilePathFallback", func(t *testing.T) {
		// When the name doesn't match a known template, loadTemplateOrFile
		// treats it as a file path. Test that LoadFile works for a real file.
		bundle := loadTestBundle(t) // uses testdata/policy.json

		// Verify it loaded successfully.
		if len(bundle.Attributes) == 0 {
			t.Fatal("loaded bundle has no attributes")
		}
		if len(bundle.Identities) == 0 {
			t.Fatal("loaded bundle has no identities")
		}
	})

	t.Run("UnknownTemplateNameNotMatched", func(t *testing.T) {
		// A name that doesn't match any template should NOT match.
		unknownNames := []string{"medical", "banking", "military", "custom", ""}
		for _, name := range unknownNames {
			var found bool
			for _, available := range templates.Available() {
				if strings.EqualFold(name, available) {
					found = true
					break
				}
			}
			if found {
				t.Errorf("name %q unexpectedly matched a template", name)
			}
		}
	})

	t.Run("TemplateDescriptionsComplete", func(t *testing.T) {
		// Every available template should have a description.
		descriptions := templates.Descriptions()
		for _, name := range templates.Available() {
			desc, ok := descriptions[name]
			if !ok || desc == "" {
				t.Errorf("template %q has no description", name)
			}
		}
	})

	t.Run("AllTemplatesValidateSuccessfully", func(t *testing.T) {
		// Every template should pass validation when loaded.
		for _, name := range templates.Available() {
			bundle, err := templates.Load(name)
			if err != nil {
				t.Errorf("templates.Load(%q): %v", name, err)
				continue
			}
			// Load already validates, but let's be explicit.
			if err := bundle.Validate(); err != nil {
				t.Errorf("template %q failed validation: %v", name, err)
			}
		}
	})
}
