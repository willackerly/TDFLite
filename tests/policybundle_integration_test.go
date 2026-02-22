package tests_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/willackerly/TDFLite/internal/idplite"
	"github.com/willackerly/TDFLite/internal/policybundle"
	"github.com/willackerly/TDFLite/internal/provision"
	"golang.org/x/crypto/ssh"
)

const testdataPath = "../internal/policybundle/testdata/policy.json"

func init() {
	// Use low work factor for fast passphrase tests.
	policybundle.SetSealWorkFactor(10)
}

// loadTestBundle reads the testdata policy.json and unmarshals it into a Bundle.
func loadTestBundle(t *testing.T) *policybundle.Bundle {
	t.Helper()
	data, err := os.ReadFile(testdataPath)
	if err != nil {
		t.Fatalf("reading testdata policy.json: %v", err)
	}
	var b policybundle.Bundle
	if err := json.Unmarshal(data, &b); err != nil {
		t.Fatalf("unmarshaling policy.json: %v", err)
	}
	return &b
}

// generateSSHKeyPair creates a temp Ed25519 SSH key pair and returns (pubPath, privPath).
func generateSSHKeyPair(t *testing.T) (string, string) {
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
		t.Fatalf("creating SSH public key: %v", err)
	}
	pubPath := filepath.Join(dir, "id_ed25519.pub")
	if err := os.WriteFile(pubPath, ssh.MarshalAuthorizedKey(sshPub), 0644); err != nil {
		t.Fatalf("writing public key: %v", err)
	}

	return pubPath, privPath
}

// ---------------------------------------------------------------------------
// Test 1: Full Seal → Sign → Verify → Unseal flow with SSH key
// ---------------------------------------------------------------------------

func TestFullSealUnsealFlow(t *testing.T) {
	bundle := loadTestBundle(t)
	pubPath, privPath := generateSSHKeyPair(t)

	// Step 1: Seal with SSH key.
	if err := policybundle.SealWithSSHKey(bundle, pubPath); err != nil {
		t.Fatalf("SealWithSSHKey: %v", err)
	}

	// Step 2: Sign with SSH private key.
	if err := policybundle.SignBundle(bundle, privPath); err != nil {
		t.Fatalf("SignBundle: %v", err)
	}

	// Step 3: Verify sealed state.
	if !bundle.IsSealed() {
		t.Fatal("expected bundle.IsSealed() == true after seal + sign")
	}
	if bundle.Signature == "" {
		t.Fatal("expected bundle.Signature to be non-empty after signing")
	}

	// Step 4: Marshal to JSON (simulates writing to disk).
	sealedJSON, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		t.Fatalf("marshaling sealed bundle: %v", err)
	}

	// Step 5: Unmarshal back (simulates reading from disk).
	var loaded policybundle.Bundle
	if err := json.Unmarshal(sealedJSON, &loaded); err != nil {
		t.Fatalf("unmarshaling sealed bundle: %v", err)
	}

	// Step 6: Verify signature on the loaded bundle.
	if err := policybundle.VerifySignature(&loaded, pubPath); err != nil {
		t.Fatalf("VerifySignature on round-tripped bundle: %v", err)
	}

	// Step 7: Unseal with SSH private key.
	keys, err := policybundle.UnsealWithSSHKey(&loaded, privPath)
	if err != nil {
		t.Fatalf("UnsealWithSSHKey: %v", err)
	}

	// Step 8: Verify RSA key can sign + verify.
	testData := []byte("integration test signing payload")
	digest := sha256.Sum256(testData)

	rsaSig, err := rsa.SignPKCS1v15(rand.Reader, keys.RSAPrivate, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("RSA signing failed: %v", err)
	}
	if err := rsa.VerifyPKCS1v15(&keys.RSAPrivate.PublicKey, crypto.SHA256, digest[:], rsaSig); err != nil {
		t.Fatalf("RSA verification failed: %v", err)
	}

	// Step 9: Verify EC key can sign + verify.
	ecSig, err := ecdsa.SignASN1(rand.Reader, keys.ECPrivate, digest[:])
	if err != nil {
		t.Fatalf("EC signing failed: %v", err)
	}
	if !ecdsa.VerifyASN1(&keys.ECPrivate.PublicKey, digest[:], ecSig) {
		t.Fatal("EC verification failed")
	}

	// Step 10: Verify IDP key is a valid RSA key.
	if keys.IDPKey == nil {
		t.Fatal("IDPKey is nil")
	}
	if err := keys.IDPKey.Validate(); err != nil {
		t.Fatalf("IDPKey validation failed: %v", err)
	}

	// Step 11: Verify RSA cert is valid PEM containing a certificate.
	rsaBlock, _ := pem.Decode(keys.RSACert)
	if rsaBlock == nil {
		t.Fatal("RSACert: no PEM block found")
	}
	if rsaBlock.Type != "CERTIFICATE" {
		t.Fatalf("RSACert: expected CERTIFICATE PEM block, got %q", rsaBlock.Type)
	}
	if _, err := x509.ParseCertificate(rsaBlock.Bytes); err != nil {
		t.Fatalf("RSACert: failed to parse X.509 certificate: %v", err)
	}

	// Step 12: Verify EC cert is valid PEM containing a certificate.
	ecBlock, _ := pem.Decode(keys.ECCert)
	if ecBlock == nil {
		t.Fatal("ECCert: no PEM block found")
	}
	if ecBlock.Type != "CERTIFICATE" {
		t.Fatalf("ECCert: expected CERTIFICATE PEM block, got %q", ecBlock.Type)
	}
	if _, err := x509.ParseCertificate(ecBlock.Bytes); err != nil {
		t.Fatalf("ECCert: failed to parse X.509 certificate: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Test 2: Full Passphrase flow
// ---------------------------------------------------------------------------

func TestFullPassphraseFlow(t *testing.T) {
	bundle := loadTestBundle(t)
	passphrase := "test-integration-passphrase-2024"

	// Seal with passphrase.
	if err := policybundle.SealWithPassphrase(bundle, passphrase); err != nil {
		t.Fatalf("SealWithPassphrase: %v", err)
	}

	// Sign with passphrase mode (SHA-256 hash).
	if err := policybundle.SignBundlePassphrase(bundle); err != nil {
		t.Fatalf("SignBundlePassphrase: %v", err)
	}

	if !bundle.IsSealed() {
		t.Fatal("expected bundle.IsSealed() == true after passphrase seal + sign")
	}

	// Marshal/unmarshal round-trip.
	sealedJSON, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		t.Fatalf("marshaling sealed bundle: %v", err)
	}

	var loaded policybundle.Bundle
	if err := json.Unmarshal(sealedJSON, &loaded); err != nil {
		t.Fatalf("unmarshaling sealed bundle: %v", err)
	}

	// Verify passphrase signature.
	if err := policybundle.VerifyPassphraseSignature(&loaded); err != nil {
		t.Fatalf("VerifyPassphraseSignature on round-tripped bundle: %v", err)
	}

	// Unseal with passphrase.
	keys, err := policybundle.UnsealWithPassphrase(&loaded, passphrase)
	if err != nil {
		t.Fatalf("UnsealWithPassphrase: %v", err)
	}

	// Verify all keys are present and valid.
	if keys.RSAPrivate == nil {
		t.Fatal("RSAPrivate is nil")
	}
	if err := keys.RSAPrivate.Validate(); err != nil {
		t.Fatalf("RSA key validation: %v", err)
	}

	if keys.ECPrivate == nil {
		t.Fatal("ECPrivate is nil")
	}

	if keys.IDPKey == nil {
		t.Fatal("IDPKey is nil")
	}
	if err := keys.IDPKey.Validate(); err != nil {
		t.Fatalf("IDP key validation: %v", err)
	}

	if len(keys.RSACert) == 0 {
		t.Fatal("RSACert is empty")
	}
	if len(keys.ECCert) == 0 {
		t.Fatal("ECCert is empty")
	}

	// Verify RSA key can sign + verify.
	digest := sha256.Sum256([]byte("passphrase flow test"))
	rsaSig, err := rsa.SignPKCS1v15(rand.Reader, keys.RSAPrivate, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("RSA signing: %v", err)
	}
	if err := rsa.VerifyPKCS1v15(&keys.RSAPrivate.PublicKey, crypto.SHA256, digest[:], rsaSig); err != nil {
		t.Fatalf("RSA verification: %v", err)
	}

	// Verify EC key can sign + verify.
	ecSig, err := ecdsa.SignASN1(rand.Reader, keys.ECPrivate, digest[:])
	if err != nil {
		t.Fatalf("EC signing: %v", err)
	}
	if !ecdsa.VerifyASN1(&keys.ECPrivate.PublicKey, digest[:], ecSig) {
		t.Fatal("EC verification failed")
	}
}

// ---------------------------------------------------------------------------
// Test 3: Identity generation
// ---------------------------------------------------------------------------

func TestIdentityGeneration(t *testing.T) {
	bundle := loadTestBundle(t)

	output, err := policybundle.GenerateIdentities(bundle)
	if err != nil {
		t.Fatalf("GenerateIdentities: %v", err)
	}

	// Verify 5 user identities.
	if len(output.Users) != 5 {
		t.Fatalf("expected 5 users, got %d", len(output.Users))
	}

	// Verify 2 built-in clients (opentdf, opentdf-sdk).
	if len(output.Clients) != 2 {
		t.Fatalf("expected 2 clients, got %d", len(output.Clients))
	}

	// Build maps for lookup.
	usersByName := make(map[string]idplite.Identity, len(output.Users))
	for _, u := range output.Users {
		usersByName[u.Username] = u
	}
	clientsByID := make(map[string]idplite.Identity, len(output.Clients))
	for _, c := range output.Clients {
		clientsByID[c.ClientID] = c
	}

	// Verify expected users exist.
	expectedUsers := []string{"alice", "bob", "carol", "dave", "eve"}
	for _, name := range expectedUsers {
		if _, ok := usersByName[name]; !ok {
			t.Errorf("expected user %q not found", name)
		}
	}

	// Verify alice has correct custom claims.
	alice := usersByName["alice"]
	if alice.CustomClaims == nil {
		t.Fatal("alice has no custom claims")
	}

	aliceLevel, ok := alice.CustomClaims["classification_level"]
	if !ok {
		t.Fatal("alice missing classification_level claim")
	}
	if aliceLevel != "TOP_SECRET" {
		t.Errorf("alice classification_level: expected TOP_SECRET, got %v", aliceLevel)
	}

	aliceSCI, ok := alice.CustomClaims["sci_control_system"]
	if !ok {
		t.Fatal("alice missing sci_control_system claim")
	}
	// The claim comes through as []interface{} after JSON round-trip in the identity
	// Claims map, but GenerateIdentities copies Claims values directly, so for the
	// original bundle (not round-tripped through JSON) these are []string.
	expectedSCI := []string{"SI", "HCS", "TK"}
	switch v := aliceSCI.(type) {
	case []string:
		if !reflect.DeepEqual(v, expectedSCI) {
			t.Errorf("alice sci_control_system: expected %v, got %v", expectedSCI, v)
		}
	case []interface{}:
		if len(v) != len(expectedSCI) {
			t.Errorf("alice sci_control_system: expected %d values, got %d", len(expectedSCI), len(v))
		} else {
			for i, val := range v {
				if fmt.Sprintf("%v", val) != expectedSCI[i] {
					t.Errorf("alice sci_control_system[%d]: expected %q, got %v", i, expectedSCI[i], val)
				}
			}
		}
	default:
		t.Errorf("alice sci_control_system: unexpected type %T", aliceSCI)
	}

	// Verify eve has only classification_level = UNCLASSIFIED.
	eve := usersByName["eve"]
	if eve.CustomClaims == nil {
		t.Fatal("eve has no custom claims")
	}
	eveLevel, ok := eve.CustomClaims["classification_level"]
	if !ok {
		t.Fatal("eve missing classification_level claim")
	}
	if eveLevel != "UNCLASSIFIED" {
		t.Errorf("eve classification_level: expected UNCLASSIFIED, got %v", eveLevel)
	}
	// Eve should have exactly 1 claim (classification_level only).
	if len(eve.CustomClaims) != 1 {
		t.Errorf("eve should have exactly 1 custom claim, got %d: %v", len(eve.CustomClaims), eve.CustomClaims)
	}

	// Verify user credentials follow the default pattern: {name}-client, {name}-secret.
	for _, name := range expectedUsers {
		u := usersByName[name]
		expectedClientID := name + "-client"
		expectedClientSecret := name + "-secret"
		if u.ClientID != expectedClientID {
			t.Errorf("user %q: expected client_id %q, got %q", name, expectedClientID, u.ClientID)
		}
		if u.ClientSecret != expectedClientSecret {
			t.Errorf("user %q: expected client_secret %q, got %q", name, expectedClientSecret, u.ClientSecret)
		}
	}

	// Verify opentdf built-in client.
	opentdf, ok := clientsByID["opentdf"]
	if !ok {
		t.Fatal("opentdf client not found")
	}
	if opentdf.ClientID != "opentdf" {
		t.Errorf("opentdf client_id: expected 'opentdf', got %q", opentdf.ClientID)
	}
	if opentdf.ClientSecret != "secret" {
		t.Errorf("opentdf client_secret: expected 'secret', got %q", opentdf.ClientSecret)
	}

	// Verify opentdf-sdk built-in client.
	sdk, ok := clientsByID["opentdf-sdk"]
	if !ok {
		t.Fatal("opentdf-sdk client not found")
	}
	if sdk.ClientID != "opentdf-sdk" {
		t.Errorf("opentdf-sdk client_id: expected 'opentdf-sdk', got %q", sdk.ClientID)
	}

	// Verify identity output matches idplite JSON format (has "users" and "clients").
	outputJSON, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		t.Fatalf("marshaling identity output: %v", err)
	}

	var parsed struct {
		Users   []json.RawMessage `json:"users"`
		Clients []json.RawMessage `json:"clients"`
	}
	if err := json.Unmarshal(outputJSON, &parsed); err != nil {
		t.Fatalf("parsing identity output JSON: %v", err)
	}
	if len(parsed.Users) != 5 {
		t.Errorf("JSON output: expected 5 users, got %d", len(parsed.Users))
	}
	if len(parsed.Clients) != 2 {
		t.Errorf("JSON output: expected 2 clients, got %d", len(parsed.Clients))
	}
}

// ---------------------------------------------------------------------------
// Test 4: Provision with mock ConnectRPC server
// ---------------------------------------------------------------------------

// requestRecord stores details about an HTTP request received by the mock server.
type requestRecord struct {
	Method string
	Path   string
	Body   map[string]interface{}
}

func TestProvisionWithMockServer(t *testing.T) {
	bundle := loadTestBundle(t)

	var mu sync.Mutex
	var requests []requestRecord
	callIndex := 0

	// Pre-generate IDs for attribute values.
	// The policy has 3 attributes:
	//   classification_level (hierarchy): 4 values
	//   sci_control_system (allOf): 3 values
	//   releasable_to (allOf): 5 values
	nsID := "ns-0001"

	attrResponses := map[string]map[string]interface{}{
		"classification_level": {
			"attribute": map[string]interface{}{
				"id": "attr-cl-001",
				"values": []interface{}{
					map[string]interface{}{"id": "val-cl-001", "value": "TOP_SECRET"},
					map[string]interface{}{"id": "val-cl-002", "value": "SECRET"},
					map[string]interface{}{"id": "val-cl-003", "value": "CONFIDENTIAL"},
					map[string]interface{}{"id": "val-cl-004", "value": "UNCLASSIFIED"},
				},
			},
		},
		"sci_control_system": {
			"attribute": map[string]interface{}{
				"id": "attr-sci-001",
				"values": []interface{}{
					map[string]interface{}{"id": "val-sci-001", "value": "SI"},
					map[string]interface{}{"id": "val-sci-002", "value": "HCS"},
					map[string]interface{}{"id": "val-sci-003", "value": "TK"},
				},
			},
		},
		"releasable_to": {
			"attribute": map[string]interface{}{
				"id": "attr-rel-001",
				"values": []interface{}{
					map[string]interface{}{"id": "val-rel-001", "value": "USA"},
					map[string]interface{}{"id": "val-rel-002", "value": "GBR"},
					map[string]interface{}{"id": "val-rel-003", "value": "CAN"},
					map[string]interface{}{"id": "val-rel-004", "value": "AUS"},
					map[string]interface{}{"id": "val-rel-005", "value": "NZL"},
				},
			},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read error", 500)
			return
		}
		defer r.Body.Close()

		var bodyMap map[string]interface{}
		if err := json.Unmarshal(bodyBytes, &bodyMap); err != nil {
			// Some requests may have empty or non-object bodies; just store nil.
			bodyMap = nil
		}

		mu.Lock()
		requests = append(requests, requestRecord{
			Method: r.Method,
			Path:   r.URL.Path,
			Body:   bodyMap,
		})
		idx := callIndex
		callIndex++
		_ = idx
		mu.Unlock()

		w.Header().Set("Content-Type", "application/json")

		path := r.URL.Path
		switch {
		case strings.HasSuffix(path, "/CreateNamespace"):
			resp := map[string]interface{}{
				"namespace": map[string]interface{}{
					"id":   nsID,
					"name": "tdflite.local",
				},
			}
			json.NewEncoder(w).Encode(resp)

		case strings.HasSuffix(path, "/CreateAttribute"):
			// Look up the attribute name from the request body.
			attrName, _ := bodyMap["name"].(string)
			resp, ok := attrResponses[attrName]
			if !ok {
				http.Error(w, fmt.Sprintf("unknown attribute: %s", attrName), 400)
				return
			}
			json.NewEncoder(w).Encode(resp)

		case strings.HasSuffix(path, "/CreateSubjectMapping"):
			// Return an empty success response.
			json.NewEncoder(w).Encode(map[string]interface{}{})

		default:
			http.Error(w, "not found", 404)
		}
	}))
	defer server.Close()

	// Provision the bundle against the mock server.
	ctx := context.Background()
	err := provision.Provision(ctx, bundle, server.URL, "test-token")
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}

	mu.Lock()
	allRequests := make([]requestRecord, len(requests))
	copy(allRequests, requests)
	mu.Unlock()

	// Count request types.
	var nsCount, attrCount, smCount int
	for _, req := range allRequests {
		switch {
		case strings.HasSuffix(req.Path, "/CreateNamespace"):
			nsCount++
		case strings.HasSuffix(req.Path, "/CreateAttribute"):
			attrCount++
		case strings.HasSuffix(req.Path, "/CreateSubjectMapping"):
			smCount++
		}
	}

	// Verify call counts.
	if nsCount != 1 {
		t.Errorf("expected 1 namespace creation, got %d", nsCount)
	}
	if attrCount != 3 {
		t.Errorf("expected 3 attribute creations, got %d", attrCount)
	}
	// 4 (classification_level) + 3 (sci_control_system) + 5 (releasable_to) = 12
	if smCount != 12 {
		t.Errorf("expected 12 subject mapping creations, got %d", smCount)
	}
	// Total: 1 + 3 + 12 = 16
	totalExpected := 16
	if len(allRequests) != totalExpected {
		t.Errorf("expected %d total API calls, got %d", totalExpected, len(allRequests))
	}

	// Verify selectors are correct by examining subject mapping requests.
	selectorsByAttr := make(map[string]string) // attrValueID prefix -> selector
	for _, req := range allRequests {
		if !strings.HasSuffix(req.Path, "/CreateSubjectMapping") {
			continue
		}

		// Extract the selector from the nested request body.
		newSCS, ok := req.Body["newSubjectConditionSet"].(map[string]interface{})
		if !ok {
			t.Fatal("subject mapping missing newSubjectConditionSet")
		}
		subjectSets, ok := newSCS["subjectSets"].([]interface{})
		if !ok || len(subjectSets) == 0 {
			t.Fatal("subject mapping missing subjectSets")
		}
		ss := subjectSets[0].(map[string]interface{})
		condGroups := ss["conditionGroups"].([]interface{})
		cg := condGroups[0].(map[string]interface{})
		conditions := cg["conditions"].([]interface{})
		cond := conditions[0].(map[string]interface{})
		selector := cond["subjectExternalSelectorValue"].(string)
		valueID := req.Body["attributeValueId"].(string)

		// Map by prefix to identify which attribute this belongs to.
		switch {
		case strings.HasPrefix(valueID, "val-cl-"):
			selectorsByAttr["classification_level"] = selector
		case strings.HasPrefix(valueID, "val-sci-"):
			selectorsByAttr["sci_control_system"] = selector
		case strings.HasPrefix(valueID, "val-rel-"):
			selectorsByAttr["releasable_to"] = selector
		}
	}

	// classification_level (hierarchy) -> ".classification_level" (no brackets)
	if sel := selectorsByAttr["classification_level"]; sel != ".classification_level" {
		t.Errorf("classification_level selector: expected %q, got %q", ".classification_level", sel)
	}

	// sci_control_system (allOf) -> ".sci_control_system[]" (with brackets)
	if sel := selectorsByAttr["sci_control_system"]; sel != ".sci_control_system[]" {
		t.Errorf("sci_control_system selector: expected %q, got %q", ".sci_control_system[]", sel)
	}

	// releasable_to (allOf) -> ".releasable_to[]" (with brackets)
	if sel := selectorsByAttr["releasable_to"]; sel != ".releasable_to[]" {
		t.Errorf("releasable_to selector: expected %q, got %q", ".releasable_to[]", sel)
	}
}

// ---------------------------------------------------------------------------
// Test 5: Tamper detection
// ---------------------------------------------------------------------------

func TestTamperDetection(t *testing.T) {
	bundle := loadTestBundle(t)
	pubPath, privPath := generateSSHKeyPair(t)

	// Seal and sign.
	if err := policybundle.SealWithSSHKey(bundle, pubPath); err != nil {
		t.Fatalf("SealWithSSHKey: %v", err)
	}
	if err := policybundle.SignBundle(bundle, privPath); err != nil {
		t.Fatalf("SignBundle: %v", err)
	}

	// Marshal to JSON.
	sealedJSON, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("marshaling sealed bundle: %v", err)
	}

	// Tamper: replace "TOP_SECRET" with "TOP_TAMPER" in the JSON bytes.
	tamperedJSON := strings.Replace(string(sealedJSON), "TOP_SECRET", "TOP_TAMPER", 1)
	if tamperedJSON == string(sealedJSON) {
		t.Fatal("tampering did not change the JSON (test setup error)")
	}

	// Unmarshal the tampered JSON.
	var tampered policybundle.Bundle
	if err := json.Unmarshal([]byte(tamperedJSON), &tampered); err != nil {
		t.Fatalf("unmarshaling tampered bundle: %v", err)
	}

	// Verify signature must FAIL.
	if err := policybundle.VerifySignature(&tampered, pubPath); err == nil {
		t.Fatal("expected signature verification to FAIL on tampered bundle, but it succeeded")
	}
}

// ---------------------------------------------------------------------------
// Test 6: Seal preserves policy content
// ---------------------------------------------------------------------------

func TestSealPreservesPolicy(t *testing.T) {
	bundle := loadTestBundle(t)

	// Record original attribute names, rules, values, and identity info.
	type attrSnapshot struct {
		Name   string
		Rule   string
		Values []string
	}

	origAttrs := make([]attrSnapshot, len(bundle.Attributes))
	for i, a := range bundle.Attributes {
		vals := make([]string, len(a.Values))
		copy(vals, a.Values)
		origAttrs[i] = attrSnapshot{
			Name:   a.Name,
			Rule:   string(a.Rule),
			Values: vals,
		}
	}

	origIdentityNames := make([]string, 0, len(bundle.Identities))
	for name := range bundle.Identities {
		origIdentityNames = append(origIdentityNames, name)
	}
	sort.Strings(origIdentityNames)

	// Deep-copy identity claims for comparison.
	origClaims := make(map[string]map[string]interface{}, len(bundle.Identities))
	for name, id := range bundle.Identities {
		claimsCopy := make(map[string]interface{}, len(id.Claims))
		for k, v := range id.Claims {
			claimsCopy[k] = v
		}
		origClaims[name] = claimsCopy
	}

	pubPath, privPath := generateSSHKeyPair(t)

	// Seal + sign.
	if err := policybundle.SealWithSSHKey(bundle, pubPath); err != nil {
		t.Fatalf("SealWithSSHKey: %v", err)
	}
	if err := policybundle.SignBundle(bundle, privPath); err != nil {
		t.Fatalf("SignBundle: %v", err)
	}

	// Marshal + unmarshal (full round-trip).
	sealedJSON, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		t.Fatalf("marshaling: %v", err)
	}

	var loaded policybundle.Bundle
	if err := json.Unmarshal(sealedJSON, &loaded); err != nil {
		t.Fatalf("unmarshaling: %v", err)
	}

	// Verify all attribute names, rules, and values are identical.
	if len(loaded.Attributes) != len(origAttrs) {
		t.Fatalf("attribute count: expected %d, got %d", len(origAttrs), len(loaded.Attributes))
	}
	for i, orig := range origAttrs {
		got := loaded.Attributes[i]
		if got.Name != orig.Name {
			t.Errorf("attribute[%d] name: expected %q, got %q", i, orig.Name, got.Name)
		}
		if string(got.Rule) != orig.Rule {
			t.Errorf("attribute[%d] rule: expected %q, got %q", i, orig.Rule, got.Rule)
		}
		if !reflect.DeepEqual(got.Values, orig.Values) {
			t.Errorf("attribute[%d] values: expected %v, got %v", i, orig.Values, got.Values)
		}
	}

	// Verify all identity names are preserved.
	loadedNames := make([]string, 0, len(loaded.Identities))
	for name := range loaded.Identities {
		loadedNames = append(loadedNames, name)
	}
	sort.Strings(loadedNames)
	if !reflect.DeepEqual(loadedNames, origIdentityNames) {
		t.Errorf("identity names: expected %v, got %v", origIdentityNames, loadedNames)
	}

	// Verify identity claims are identical.
	for name, origClaimMap := range origClaims {
		loadedID, ok := loaded.Identities[name]
		if !ok {
			t.Errorf("identity %q not found after round-trip", name)
			continue
		}
		for key, origVal := range origClaimMap {
			loadedVal, ok := loadedID.Claims[key]
			if !ok {
				t.Errorf("identity %q: claim %q missing after round-trip", name, key)
				continue
			}
			// After JSON round-trip, []string becomes []interface{}, so compare as strings.
			origStr := fmt.Sprintf("%v", origVal)
			loadedStr := fmt.Sprintf("%v", loadedVal)
			if origStr != loadedStr {
				t.Errorf("identity %q: claim %q: expected %v, got %v", name, key, origVal, loadedVal)
			}
		}
	}

	// Verify the JSON is human-readable (policy fields are plaintext, not encrypted).
	jsonStr := string(sealedJSON)
	if !strings.Contains(jsonStr, "classification_level") {
		t.Error("sealed JSON does not contain 'classification_level' in plaintext")
	}
	if !strings.Contains(jsonStr, "TOP_SECRET") {
		t.Error("sealed JSON does not contain 'TOP_SECRET' in plaintext")
	}
	if !strings.Contains(jsonStr, "alice") {
		t.Error("sealed JSON does not contain 'alice' in plaintext")
	}
	if !strings.Contains(jsonStr, "hierarchy") {
		t.Error("sealed JSON does not contain 'hierarchy' in plaintext")
	}
}
