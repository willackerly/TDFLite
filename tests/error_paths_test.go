package tests_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/willackerly/TDFLite/internal/policybundle"
	"github.com/willackerly/TDFLite/internal/provision"
	"golang.org/x/crypto/ssh"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// makeMinimalBundle creates a minimal valid bundle for testing.
func makeMinimalBundle() *policybundle.Bundle {
	return &policybundle.Bundle{
		Attributes: []policybundle.Attribute{
			{Name: "level", Rule: policybundle.RuleHierarchy, Values: []string{"high", "low"}},
		},
		Identities: map[string]policybundle.Identity{
			"user1": {Claims: map[string]interface{}{"level": "high"}},
		},
	}
}

// generateSSHKeyPairForTest creates a temp Ed25519 SSH key pair and returns (pubPath, privPath).
// Named differently from the helper in the integration test file to avoid redeclaration.
func generateSSHKeyPairForTest(t *testing.T) (string, string) {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating ed25519 key: %v", err)
	}

	dir := t.TempDir()

	privPEM, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatalf("marshaling private key: %v", err)
	}
	privPath := filepath.Join(dir, "id_ed25519")
	if err := os.WriteFile(privPath, pem.EncodeToMemory(privPEM), 0600); err != nil {
		t.Fatalf("writing private key: %v", err)
	}

	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("creating SSH public key: %v", err)
	}
	pubPath := filepath.Join(dir, "id_ed25519.pub")
	if err := os.WriteFile(pubPath, ssh.MarshalAuthorizedKey(sshPub), 0644); err != nil {
		t.Fatalf("writing public key: %v", err)
	}

	return pubPath, privPath
}

// ---------------------------------------------------------------------------
// Cross-Mode Tests
// ---------------------------------------------------------------------------

func TestSSHSealPassphraseUnseal(t *testing.T) {
	bundle := makeMinimalBundle()
	pubPath, _ := generateSSHKeyPairForTest(t)

	if err := policybundle.SealWithSSHKey(bundle, pubPath); err != nil {
		t.Fatalf("SealWithSSHKey: %v", err)
	}

	// Try unsealing with a passphrase — must fail.
	_, err := policybundle.UnsealWithPassphrase(bundle, "wrong-mode")
	if err == nil {
		t.Fatal("expected UnsealWithPassphrase to fail on SSH-sealed bundle, but it succeeded")
	}
	t.Logf("expected error: %v", err)
}

func TestPassphraseSealSSHUnseal(t *testing.T) {
	bundle := makeMinimalBundle()

	if err := policybundle.SealWithPassphrase(bundle, "my-passphrase"); err != nil {
		t.Fatalf("SealWithPassphrase: %v", err)
	}

	// Generate an SSH key and try to unseal — must fail.
	_, privPath := generateSSHKeyPairForTest(t)

	_, err := policybundle.UnsealWithSSHKey(bundle, privPath)
	if err == nil {
		t.Fatal("expected UnsealWithSSHKey to fail on passphrase-sealed bundle, but it succeeded")
	}
	t.Logf("expected error: %v", err)
}

func TestSSHSignPassphraseVerify(t *testing.T) {
	bundle := makeMinimalBundle()
	pubPath, privPath := generateSSHKeyPairForTest(t)

	if err := policybundle.SealWithSSHKey(bundle, pubPath); err != nil {
		t.Fatalf("SealWithSSHKey: %v", err)
	}
	if err := policybundle.SignBundle(bundle, privPath); err != nil {
		t.Fatalf("SignBundle: %v", err)
	}

	// SSH signatures are cryptographic; passphrase verification is a SHA-256 hash.
	// The passphrase verifier recomputes SHA-256 and compares, so it will mismatch
	// with the SSH signature.
	err := policybundle.VerifyPassphraseSignature(bundle)
	if err == nil {
		t.Fatal("expected VerifyPassphraseSignature to fail on SSH-signed bundle, but it succeeded")
	}
	t.Logf("expected error: %v", err)
}

func TestPassphraseSignSSHVerify(t *testing.T) {
	bundle := makeMinimalBundle()

	if err := policybundle.SealWithPassphrase(bundle, "my-passphrase"); err != nil {
		t.Fatalf("SealWithPassphrase: %v", err)
	}
	if err := policybundle.SignBundlePassphrase(bundle); err != nil {
		t.Fatalf("SignBundlePassphrase: %v", err)
	}

	// Generate a random SSH key and try to verify — must fail.
	pubPath, _ := generateSSHKeyPairForTest(t)

	err := policybundle.VerifySignature(bundle, pubPath)
	if err == nil {
		t.Fatal("expected VerifySignature with random SSH key to fail on passphrase-signed bundle, but it succeeded")
	}
	t.Logf("expected error: %v", err)
}

// ---------------------------------------------------------------------------
// Wrong Key Tests
// ---------------------------------------------------------------------------

func TestUnsealWithWrongSSHKey(t *testing.T) {
	bundle := makeMinimalBundle()
	pubA, _ := generateSSHKeyPairForTest(t)
	_, privB := generateSSHKeyPairForTest(t)

	if err := policybundle.SealWithSSHKey(bundle, pubA); err != nil {
		t.Fatalf("SealWithSSHKey: %v", err)
	}

	// Try unsealing with key B — must fail.
	_, err := policybundle.UnsealWithSSHKey(bundle, privB)
	if err == nil {
		t.Fatal("expected UnsealWithSSHKey to fail with wrong key, but it succeeded")
	}
	t.Logf("expected error: %v", err)
}

func TestUnsealWithWrongPassphrase(t *testing.T) {
	bundle := makeMinimalBundle()

	if err := policybundle.SealWithPassphrase(bundle, "correct-passphrase"); err != nil {
		t.Fatalf("SealWithPassphrase: %v", err)
	}

	_, err := policybundle.UnsealWithPassphrase(bundle, "wrong-passphrase")
	if err == nil {
		t.Fatal("expected UnsealWithPassphrase to fail with wrong passphrase, but it succeeded")
	}
	t.Logf("expected error: %v", err)
}

func TestVerifyWithWrongSSHKey(t *testing.T) {
	bundle := makeMinimalBundle()
	pubA, privA := generateSSHKeyPairForTest(t)
	pubB, _ := generateSSHKeyPairForTest(t)

	if err := policybundle.SealWithSSHKey(bundle, pubA); err != nil {
		t.Fatalf("SealWithSSHKey: %v", err)
	}
	if err := policybundle.SignBundle(bundle, privA); err != nil {
		t.Fatalf("SignBundle: %v", err)
	}

	// Verify with key B — must fail.
	err := policybundle.VerifySignature(bundle, pubB)
	if err == nil {
		t.Fatal("expected VerifySignature to fail with wrong SSH key, but it succeeded")
	}
	t.Logf("expected error: %v", err)
}

func TestRebindWithWrongOldKey(t *testing.T) {
	bundle := makeMinimalBundle()
	pubA, _ := generateSSHKeyPairForTest(t)
	_, privB := generateSSHKeyPairForTest(t) // wrong old key
	_, privC := generateSSHKeyPairForTest(t) // new key

	if err := policybundle.SealWithSSHKey(bundle, pubA); err != nil {
		t.Fatalf("SealWithSSHKey: %v", err)
	}

	// Try rebinding with wrong old key B — must fail.
	err := policybundle.RebindSSHKey(bundle, privB, privC)
	if err == nil {
		t.Fatal("expected RebindSSHKey to fail with wrong old key, but it succeeded")
	}
	t.Logf("expected error: %v", err)
}

// ---------------------------------------------------------------------------
// Invalid Input Tests
// ---------------------------------------------------------------------------

func TestSealUnsealedBundle(t *testing.T) {
	// Sealing a fresh bundle (no sealed section yet) — should succeed normally.
	bundle := makeMinimalBundle()
	pubPath, _ := generateSSHKeyPairForTest(t)

	if err := policybundle.SealWithSSHKey(bundle, pubPath); err != nil {
		t.Fatalf("SealWithSSHKey on fresh bundle should succeed: %v", err)
	}
	if bundle.Sealed == nil {
		t.Fatal("expected Sealed section to be populated after sealing")
	}
	if bundle.Sealed.KASKeys == "" {
		t.Fatal("expected Sealed.KASKeys to be non-empty")
	}
	if bundle.Sealed.IDPKey == "" {
		t.Fatal("expected Sealed.IDPKey to be non-empty")
	}
}

func TestSealAlreadySealedBundle(t *testing.T) {
	bundle := makeMinimalBundle()
	pubPath, _ := generateSSHKeyPairForTest(t)

	// Seal once.
	if err := policybundle.SealWithSSHKey(bundle, pubPath); err != nil {
		t.Fatalf("first SealWithSSHKey: %v", err)
	}
	firstKASKeys := bundle.Sealed.KASKeys

	// Seal again — should overwrite (new key material generated).
	if err := policybundle.SealWithSSHKey(bundle, pubPath); err != nil {
		t.Fatalf("second SealWithSSHKey: %v", err)
	}

	// The KAS keys should differ because new keys are generated each time.
	if bundle.Sealed.KASKeys == firstKASKeys {
		t.Error("expected second seal to produce different KAS keys, but they are the same")
	}
}

func TestSignUnsealedBundle(t *testing.T) {
	bundle := makeMinimalBundle()
	_, privPath := generateSSHKeyPairForTest(t)

	// The Sealed section is nil. Signing should still work (it signs the canonical
	// bytes regardless of whether Sealed is populated).
	err := policybundle.SignBundle(bundle, privPath)
	if err != nil {
		t.Fatalf("SignBundle on unsealed bundle: %v", err)
	}
	if bundle.Signature == "" {
		t.Fatal("expected Signature to be set after SignBundle")
	}
}

func TestUnsealUnsealedBundle(t *testing.T) {
	bundle := makeMinimalBundle()
	_, privPath := generateSSHKeyPairForTest(t)

	// No sealed section — unseal must fail gracefully.
	_, err := policybundle.UnsealWithSSHKey(bundle, privPath)
	if err == nil {
		t.Fatal("expected UnsealWithSSHKey to fail on unsealed bundle, but it succeeded")
	}
	if !strings.Contains(err.Error(), "not sealed") {
		t.Errorf("expected error message to mention 'not sealed', got: %v", err)
	}

	// Also test passphrase unseal on unsealed bundle.
	_, err = policybundle.UnsealWithPassphrase(bundle, "any")
	if err == nil {
		t.Fatal("expected UnsealWithPassphrase to fail on unsealed bundle, but it succeeded")
	}
	if !strings.Contains(err.Error(), "not sealed") {
		t.Errorf("expected error message to mention 'not sealed', got: %v", err)
	}
}

func TestVerifyUnsignedBundle(t *testing.T) {
	bundle := makeMinimalBundle()
	pubPath, _ := generateSSHKeyPairForTest(t)

	// No signature — verify must fail.
	err := policybundle.VerifySignature(bundle, pubPath)
	if err == nil {
		t.Fatal("expected VerifySignature to fail on unsigned bundle, but it succeeded")
	}
	if !strings.Contains(err.Error(), "no signature") {
		t.Errorf("expected error message to mention 'no signature', got: %v", err)
	}

	// Also test passphrase verification on unsigned bundle.
	err = policybundle.VerifyPassphraseSignature(bundle)
	if err == nil {
		t.Fatal("expected VerifyPassphraseSignature to fail on unsigned bundle, but it succeeded")
	}
	if !strings.Contains(err.Error(), "no signature") {
		t.Errorf("expected error message to mention 'no signature', got: %v", err)
	}
}

func TestLoadInvalidJSON(t *testing.T) {
	_, err := policybundle.LoadJSON([]byte("this is not json at all {{{"))
	if err == nil {
		t.Fatal("expected LoadJSON to fail on garbage input, but it succeeded")
	}
	t.Logf("expected error: %v", err)
}

func TestLoadValidJSONInvalidPolicy(t *testing.T) {
	// Valid JSON but missing required fields.
	data := []byte(`{"attributes": [], "identities": {}}`)
	_, err := policybundle.LoadJSON(data)
	if err == nil {
		t.Fatal("expected LoadJSON to fail on empty policy, but it succeeded")
	}
	errMsg := err.Error()
	if !strings.Contains(errMsg, "attribute") {
		t.Errorf("expected error to mention missing attributes, got: %v", err)
	}
	if !strings.Contains(errMsg, "identity") || !strings.Contains(errMsg, "identit") {
		t.Errorf("expected error to mention missing identities, got: %v", err)
	}
	t.Logf("expected error: %v", err)
}

func TestLoadFileNonexistent(t *testing.T) {
	_, err := policybundle.LoadFile("/nonexistent/path/to/policy.json")
	if err == nil {
		t.Fatal("expected LoadFile to fail on nonexistent path, but it succeeded")
	}
	t.Logf("expected error: %v", err)
}

// ---------------------------------------------------------------------------
// Validation Edge Cases
// ---------------------------------------------------------------------------

func TestValidateEmptyBundle(t *testing.T) {
	b := &policybundle.Bundle{}
	err := b.Validate()
	if err == nil {
		t.Fatal("expected empty bundle to fail validation")
	}
	errMsg := err.Error()
	if !strings.Contains(errMsg, "attribute") {
		t.Errorf("expected error to mention missing attributes, got: %v", err)
	}
	if !strings.Contains(errMsg, "identity") || !strings.Contains(errMsg, "identit") {
		t.Errorf("expected error to mention missing identities, got: %v", err)
	}
}

func TestValidateAttributeOnlyNoIdentities(t *testing.T) {
	b := &policybundle.Bundle{
		Attributes: []policybundle.Attribute{
			{Name: "level", Rule: policybundle.RuleHierarchy, Values: []string{"high", "low"}},
		},
		Identities: map[string]policybundle.Identity{},
	}
	err := b.Validate()
	if err == nil {
		t.Fatal("expected validation to fail with no identities")
	}
	if !strings.Contains(err.Error(), "identity") && !strings.Contains(err.Error(), "identit") {
		t.Errorf("expected error to mention missing identities, got: %v", err)
	}
}

func TestValidateIdentitiesOnlyNoAttributes(t *testing.T) {
	b := &policybundle.Bundle{
		Attributes: []policybundle.Attribute{},
		Identities: map[string]policybundle.Identity{
			"user1": {Claims: map[string]interface{}{}},
		},
	}
	err := b.Validate()
	if err == nil {
		t.Fatal("expected validation to fail with no attributes")
	}
	if !strings.Contains(err.Error(), "attribute") {
		t.Errorf("expected error to mention missing attributes, got: %v", err)
	}
}

func TestValidateIdentityClaimNotInAttributes(t *testing.T) {
	b := &policybundle.Bundle{
		Attributes: []policybundle.Attribute{
			{Name: "level", Rule: policybundle.RuleHierarchy, Values: []string{"high", "low"}},
		},
		Identities: map[string]policybundle.Identity{
			"user1": {Claims: map[string]interface{}{"nonexistent_attr": "value"}},
		},
	}
	err := b.Validate()
	if err == nil {
		t.Fatal("expected validation to fail when claim references nonexistent attribute")
	}
	if !strings.Contains(err.Error(), "nonexistent_attr") {
		t.Errorf("expected error to mention the nonexistent claim name, got: %v", err)
	}
	if !strings.Contains(err.Error(), "does not match") {
		t.Errorf("expected error to say 'does not match any attribute', got: %v", err)
	}
}

func TestValidateHierarchyClaimAsArray(t *testing.T) {
	b := &policybundle.Bundle{
		Attributes: []policybundle.Attribute{
			{Name: "level", Rule: policybundle.RuleHierarchy, Values: []string{"high", "low"}},
		},
		Identities: map[string]policybundle.Identity{
			"user1": {Claims: map[string]interface{}{"level": []string{"high", "low"}}},
		},
	}
	err := b.Validate()
	if err == nil {
		t.Fatal("expected validation to fail when hierarchy claim is an array")
	}
	if !strings.Contains(err.Error(), "must be a string") {
		t.Errorf("expected error to say claim must be a string, got: %v", err)
	}
}

func TestValidateAllOfClaimAsScalar(t *testing.T) {
	b := &policybundle.Bundle{
		Attributes: []policybundle.Attribute{
			{Name: "tags", Rule: policybundle.RuleAllOf, Values: []string{"a", "b", "c"}},
		},
		Identities: map[string]policybundle.Identity{
			"user1": {Claims: map[string]interface{}{"tags": "a"}},
		},
	}
	err := b.Validate()
	if err == nil {
		t.Fatal("expected validation to fail when allOf claim is a scalar")
	}
	if !strings.Contains(err.Error(), "must be an array") {
		t.Errorf("expected error to say claim must be an array, got: %v", err)
	}
}

func TestValidateValueNotInAttributeValues(t *testing.T) {
	b := &policybundle.Bundle{
		Attributes: []policybundle.Attribute{
			{Name: "level", Rule: policybundle.RuleHierarchy, Values: []string{"high", "low"}},
		},
		Identities: map[string]policybundle.Identity{
			"user1": {Claims: map[string]interface{}{"level": "medium"}},
		},
	}
	err := b.Validate()
	if err == nil {
		t.Fatal("expected validation to fail when claim value is not in attribute values")
	}
	if !strings.Contains(err.Error(), "medium") {
		t.Errorf("expected error to mention the invalid value 'medium', got: %v", err)
	}
	if !strings.Contains(err.Error(), "not in attribute values") {
		t.Errorf("expected error to say 'not in attribute values', got: %v", err)
	}
}

func TestValidateDuplicateAttributeNames(t *testing.T) {
	b := &policybundle.Bundle{
		Attributes: []policybundle.Attribute{
			{Name: "level", Rule: policybundle.RuleHierarchy, Values: []string{"high", "low"}},
			{Name: "level", Rule: policybundle.RuleAnyOf, Values: []string{"a", "b"}},
		},
		Identities: map[string]policybundle.Identity{
			"user1": {Claims: map[string]interface{}{"level": "high"}},
		},
	}
	err := b.Validate()
	if err == nil {
		t.Fatal("expected validation to fail with duplicate attribute names")
	}
	if !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("expected error to mention 'duplicate', got: %v", err)
	}
}

func TestValidateEmptyAttributeName(t *testing.T) {
	b := &policybundle.Bundle{
		Attributes: []policybundle.Attribute{
			{Name: "", Rule: policybundle.RuleHierarchy, Values: []string{"high"}},
		},
		Identities: map[string]policybundle.Identity{
			"user1": {Claims: map[string]interface{}{}},
		},
	}
	err := b.Validate()
	if err == nil {
		t.Fatal("expected validation to fail with empty attribute name")
	}
	if !strings.Contains(err.Error(), "name is required") {
		t.Errorf("expected error to mention 'name is required', got: %v", err)
	}
}

func TestValidateEmptyAttributeValues(t *testing.T) {
	b := &policybundle.Bundle{
		Attributes: []policybundle.Attribute{
			{Name: "level", Rule: policybundle.RuleHierarchy, Values: []string{}},
		},
		Identities: map[string]policybundle.Identity{
			"user1": {Claims: map[string]interface{}{}},
		},
	}
	err := b.Validate()
	if err == nil {
		t.Fatal("expected validation to fail with empty attribute values")
	}
	if !strings.Contains(err.Error(), "at least one value") {
		t.Errorf("expected error to mention 'at least one value', got: %v", err)
	}
}

func TestValidateInvalidRule(t *testing.T) {
	b := &policybundle.Bundle{
		Attributes: []policybundle.Attribute{
			{Name: "level", Rule: policybundle.AttributeRule("invalid"), Values: []string{"high"}},
		},
		Identities: map[string]policybundle.Identity{
			"user1": {Claims: map[string]interface{}{}},
		},
	}
	err := b.Validate()
	if err == nil {
		t.Fatal("expected validation to fail with invalid rule")
	}
	if !strings.Contains(err.Error(), "invalid rule") {
		t.Errorf("expected error to mention 'invalid rule', got: %v", err)
	}
}

func TestValidateMultipleErrors(t *testing.T) {
	b := &policybundle.Bundle{
		Attributes: []policybundle.Attribute{
			{Name: "", Rule: policybundle.RuleHierarchy, Values: []string{"high"}},
			{Name: "tags", Rule: policybundle.AttributeRule("bogus"), Values: []string{}},
		},
		Identities: map[string]policybundle.Identity{},
	}
	err := b.Validate()
	if err == nil {
		t.Fatal("expected validation to fail with multiple errors")
	}

	errMsg := err.Error()
	// Should report ALL of:
	// 1. empty attribute name
	// 2. invalid rule "bogus"
	// 3. empty values for "tags"
	// 4. no identities
	errorChecks := []struct {
		substring string
		label     string
	}{
		{"name is required", "empty attribute name"},
		{"invalid rule", "invalid rule type"},
		{"at least one value", "empty attribute values"},
		{"at least one identity", "no identities"},
	}

	for _, check := range errorChecks {
		if !strings.Contains(errMsg, check.substring) {
			t.Errorf("expected error to include %q (%s), got: %v", check.substring, check.label, errMsg)
		}
	}
	t.Logf("all errors reported: %v", err)
}

// ---------------------------------------------------------------------------
// Identity Generation Edge Cases
// ---------------------------------------------------------------------------

func TestGenerateIdentitiesNoClaimsIdentity(t *testing.T) {
	b := &policybundle.Bundle{
		Attributes: []policybundle.Attribute{
			{Name: "level", Rule: policybundle.RuleHierarchy, Values: []string{"high", "low"}},
		},
		Identities: map[string]policybundle.Identity{
			"admin-user": {Admin: true, Claims: map[string]interface{}{}},
		},
	}

	output, err := policybundle.GenerateIdentities(b)
	if err != nil {
		t.Fatalf("GenerateIdentities: %v", err)
	}

	if len(output.Users) != 1 {
		t.Fatalf("expected 1 user, got %d", len(output.Users))
	}

	user := output.Users[0]
	if user.Username != "admin-user" {
		t.Errorf("expected username 'admin-user', got %q", user.Username)
	}

	// Admin should have the admin role.
	foundAdmin := false
	for _, role := range user.Roles {
		if role == "opentdf-admin" {
			foundAdmin = true
		}
	}
	if !foundAdmin {
		t.Errorf("expected admin-user to have opentdf-admin role, got roles: %v", user.Roles)
	}

	// No claims means CustomClaims should be nil or empty.
	if user.CustomClaims != nil && len(user.CustomClaims) > 0 {
		t.Errorf("expected no custom claims for admin with empty Claims, got: %v", user.CustomClaims)
	}
}

func TestGenerateIdentitiesEmptyBundle(t *testing.T) {
	b := &policybundle.Bundle{
		Attributes: []policybundle.Attribute{
			{Name: "level", Rule: policybundle.RuleHierarchy, Values: []string{"high"}},
		},
		Identities: map[string]policybundle.Identity{},
	}

	output, err := policybundle.GenerateIdentities(b)
	if err != nil {
		t.Fatalf("GenerateIdentities: %v", err)
	}

	if len(output.Users) != 0 {
		t.Errorf("expected 0 users, got %d", len(output.Users))
	}

	// Built-in clients should always be present.
	if len(output.Clients) != 2 {
		t.Errorf("expected 2 built-in clients, got %d", len(output.Clients))
	}

	// Verify the built-in clients are opentdf-sdk and opentdf.
	clientIDs := make(map[string]bool)
	for _, c := range output.Clients {
		clientIDs[c.ClientID] = true
	}
	if !clientIDs["opentdf"] {
		t.Error("missing built-in client 'opentdf'")
	}
	if !clientIDs["opentdf-sdk"] {
		t.Error("missing built-in client 'opentdf-sdk'")
	}
}

// ---------------------------------------------------------------------------
// Provision Error Cases
// ---------------------------------------------------------------------------

func TestProvisionServerError(t *testing.T) {
	bundle := makeMinimalBundle()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(500)
		resp := map[string]string{"code": "internal", "message": "server error"}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	ctx := context.Background()
	err := provision.Provision(ctx, bundle, server.URL, "test-token")
	if err == nil {
		t.Fatal("expected Provision to fail when server returns 500, but it succeeded")
	}
	t.Logf("expected error: %v", err)
}

func TestProvisionAuthFailure(t *testing.T) {
	bundle := makeMinimalBundle()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(401)
		resp := map[string]string{"code": "unauthenticated", "message": "invalid token"}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	ctx := context.Background()
	err := provision.Provision(ctx, bundle, server.URL, "bad-token")
	if err == nil {
		t.Fatal("expected Provision to fail when server returns 401, but it succeeded")
	}
	t.Logf("expected error: %v", err)
}

func TestProvisionInvalidRuleType(t *testing.T) {
	_, err := provision.MapRuleType(policybundle.AttributeRule("invalid"))
	if err == nil {
		t.Fatal("expected MapRuleType to fail with invalid rule, but it succeeded")
	}
	if !strings.Contains(err.Error(), "unknown rule type") {
		t.Errorf("expected error to mention 'unknown rule type', got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Additional: Provision with partial server failure (attribute creation fails)
// ---------------------------------------------------------------------------

func TestProvisionAttributeCreationFailure(t *testing.T) {
	bundle := makeMinimalBundle()

	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.Header().Set("Content-Type", "application/json")

		path := r.URL.Path

		// Read and discard body.
		io.ReadAll(r.Body)
		r.Body.Close()

		switch {
		case strings.HasSuffix(path, "/CreateNamespace"):
			resp := map[string]interface{}{
				"namespace": map[string]interface{}{"id": "ns-001", "name": "tdflite.local"},
			}
			json.NewEncoder(w).Encode(resp)

		case strings.HasSuffix(path, "/CreateAttribute"):
			// Return a non-retryable error for attribute creation.
			w.WriteHeader(400)
			resp := map[string]string{"code": "invalid_argument", "message": "bad attribute"}
			json.NewEncoder(w).Encode(resp)

		default:
			w.WriteHeader(404)
			fmt.Fprintf(w, `{"code":"not_found","message":"not found"}`)
		}
	}))
	defer server.Close()

	ctx := context.Background()
	err := provision.Provision(ctx, bundle, server.URL, "test-token")
	if err == nil {
		t.Fatal("expected Provision to fail when attribute creation fails, but it succeeded")
	}
	t.Logf("expected error: %v", err)
}
