package tests_test

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/willackerly/TDFLite/internal/policybundle"
	"github.com/willackerly/TDFLite/internal/provision"
)

// ---------------------------------------------------------------------------
// Test 1: TestLargePolicyBundle
// 20 attributes (mix of rule types), 10-20 values each, 50 identities.
// Full pipeline: seal → sign → round-trip → verify → unseal → identities → provision mock.
// ---------------------------------------------------------------------------

func TestLargePolicyBundle(t *testing.T) {
	ruleTypes := []policybundle.AttributeRule{
		policybundle.RuleHierarchy,
		policybundle.RuleAllOf,
		policybundle.RuleAnyOf,
	}

	// Create 20 attributes with 10-20 values each.
	attrs := make([]policybundle.Attribute, 20)
	totalValues := 0
	for i := 0; i < 20; i++ {
		rule := ruleTypes[i%3]
		numValues := 10 + (i % 11) // 10 to 20 values
		values := make([]string, numValues)
		for j := 0; j < numValues; j++ {
			values[j] = fmt.Sprintf("val_%d_%d", i, j)
		}
		attrs[i] = policybundle.Attribute{
			Name:   fmt.Sprintf("attr_%02d", i),
			Rule:   rule,
			Values: values,
		}
		totalValues += numValues
	}

	// Create 50 identities with various claim combinations.
	identities := make(map[string]policybundle.Identity, 50)
	for i := 0; i < 50; i++ {
		claims := make(map[string]interface{})
		for j := 0; j < 20; j++ {
			attr := attrs[j]
			switch attr.Rule {
			case policybundle.RuleHierarchy:
				// Pick a value based on identity index.
				claims[attr.Name] = attr.Values[i%len(attr.Values)]
			case policybundle.RuleAllOf, policybundle.RuleAnyOf:
				// Give 1 to 3 values from the attribute.
				count := 1 + (i % 3)
				if count > len(attr.Values) {
					count = len(attr.Values)
				}
				arr := make([]string, count)
				for k := 0; k < count; k++ {
					arr[k] = attr.Values[(i+k)%len(attr.Values)]
				}
				claims[attr.Name] = arr
			}
		}
		name := fmt.Sprintf("user_%02d", i)
		identities[name] = policybundle.Identity{
			Claims: claims,
			Admin:  i == 0, // first user is admin
		}
	}

	bundle := &policybundle.Bundle{
		Attributes: attrs,
		Identities: identities,
	}

	// Validate.
	if err := bundle.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	// Seal + sign + round-trip + verify + unseal (using passphrase for speed).
	passphrase := "large-bundle-stress-test"
	if err := policybundle.SealWithPassphrase(bundle, passphrase); err != nil {
		t.Fatalf("SealWithPassphrase: %v", err)
	}
	if err := policybundle.SignBundlePassphrase(bundle); err != nil {
		t.Fatalf("SignBundlePassphrase: %v", err)
	}

	sealedJSON, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var loaded policybundle.Bundle
	if err := json.Unmarshal(sealedJSON, &loaded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if err := policybundle.VerifyPassphraseSignature(&loaded); err != nil {
		t.Fatalf("VerifyPassphraseSignature: %v", err)
	}

	keys, err := policybundle.UnsealWithPassphrase(&loaded, passphrase)
	if err != nil {
		t.Fatalf("UnsealWithPassphrase: %v", err)
	}
	if keys.RSAPrivate == nil || keys.ECPrivate == nil || keys.IDPKey == nil {
		t.Fatal("unseal returned nil keys")
	}

	// GenerateIdentities: 50 users + 2 built-ins.
	output, err := policybundle.GenerateIdentities(&loaded)
	if err != nil {
		t.Fatalf("GenerateIdentities: %v", err)
	}
	if len(output.Users) != 50 {
		t.Errorf("expected 50 users, got %d", len(output.Users))
	}
	if len(output.Clients) != 2 {
		t.Errorf("expected 2 built-in clients, got %d", len(output.Clients))
	}

	// Provision against mock: count API calls.
	var mu sync.Mutex
	var nsCount, attrCount, smCount int

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, _ := io.ReadAll(r.Body)
		defer r.Body.Close()
		var bodyMap map[string]interface{}
		json.Unmarshal(bodyBytes, &bodyMap)

		w.Header().Set("Content-Type", "application/json")
		path := r.URL.Path

		mu.Lock()
		defer mu.Unlock()

		switch {
		case strings.HasSuffix(path, "/CreateNamespace"):
			nsCount++
			json.NewEncoder(w).Encode(map[string]interface{}{
				"namespace": map[string]interface{}{"id": "ns-large", "name": "tdflite.local"},
			})
		case strings.HasSuffix(path, "/CreateAttribute"):
			attrCount++
			attrName, _ := bodyMap["name"].(string)
			// Find the attribute to return correct values.
			var vals []interface{}
			for _, a := range loaded.Attributes {
				if a.Name == attrName {
					for vi, v := range a.Values {
						vals = append(vals, map[string]interface{}{
							"id":    fmt.Sprintf("val-%s-%d", attrName, vi),
							"value": v,
						})
					}
					break
				}
			}
			json.NewEncoder(w).Encode(map[string]interface{}{
				"attribute": map[string]interface{}{
					"id":     fmt.Sprintf("attr-%s", attrName),
					"values": vals,
				},
			})
		case strings.HasSuffix(path, "/CreateSubjectMapping"):
			smCount++
			json.NewEncoder(w).Encode(map[string]interface{}{})
		default:
			http.Error(w, "not found", 404)
		}
	}))
	defer server.Close()

	if err := provision.Provision(context.Background(), &loaded, server.URL, "test-token"); err != nil {
		t.Fatalf("Provision: %v", err)
	}

	// Verify counts: 1 namespace + 20 attributes + totalValues subject mappings.
	if nsCount != 1 {
		t.Errorf("expected 1 namespace creation, got %d", nsCount)
	}
	if attrCount != 20 {
		t.Errorf("expected 20 attribute creations, got %d", attrCount)
	}
	if smCount != totalValues {
		t.Errorf("expected %d subject mapping creations, got %d", totalValues, smCount)
	}
}

// ---------------------------------------------------------------------------
// Test 2: TestMinimalPolicyBundle
// The absolute minimum valid policy: 1 attribute, 1 value, 1 identity.
// Full pipeline: validate → seal → sign → round-trip → verify → unseal → identities → provision.
// ---------------------------------------------------------------------------

func TestMinimalPolicyBundle(t *testing.T) {
	bundle := &policybundle.Bundle{
		Attributes: []policybundle.Attribute{
			{Name: "level", Rule: policybundle.RuleHierarchy, Values: []string{"basic"}},
		},
		Identities: map[string]policybundle.Identity{
			"solo": {Claims: map[string]interface{}{"level": "basic"}},
		},
	}

	// Validate.
	if err := bundle.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	// Seal with passphrase.
	passphrase := "minimal"
	if err := policybundle.SealWithPassphrase(bundle, passphrase); err != nil {
		t.Fatalf("SealWithPassphrase: %v", err)
	}
	if err := policybundle.SignBundlePassphrase(bundle); err != nil {
		t.Fatalf("SignBundlePassphrase: %v", err)
	}

	// Round-trip.
	data, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var loaded policybundle.Bundle
	if err := json.Unmarshal(data, &loaded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// Verify + unseal.
	if err := policybundle.VerifyPassphraseSignature(&loaded); err != nil {
		t.Fatalf("VerifyPassphraseSignature: %v", err)
	}
	keys, err := policybundle.UnsealWithPassphrase(&loaded, passphrase)
	if err != nil {
		t.Fatalf("UnsealWithPassphrase: %v", err)
	}
	if keys.RSAPrivate == nil || keys.ECPrivate == nil || keys.IDPKey == nil {
		t.Fatal("unseal returned nil keys")
	}
	if len(keys.RSACert) == 0 || len(keys.ECCert) == 0 {
		t.Fatal("unseal returned empty certs")
	}

	// Identities: 1 user + 2 built-ins.
	output, err := policybundle.GenerateIdentities(&loaded)
	if err != nil {
		t.Fatalf("GenerateIdentities: %v", err)
	}
	if len(output.Users) != 1 {
		t.Errorf("expected 1 user, got %d", len(output.Users))
	}
	if output.Users[0].Username != "solo" {
		t.Errorf("expected username 'solo', got %q", output.Users[0].Username)
	}
	if len(output.Clients) != 2 {
		t.Errorf("expected 2 built-in clients, got %d", len(output.Clients))
	}

	// Provision with mock.
	var smCount int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, _ := io.ReadAll(r.Body)
		defer r.Body.Close()
		var bodyMap map[string]interface{}
		json.Unmarshal(bodyBytes, &bodyMap)

		w.Header().Set("Content-Type", "application/json")
		path := r.URL.Path

		switch {
		case strings.HasSuffix(path, "/CreateNamespace"):
			json.NewEncoder(w).Encode(map[string]interface{}{
				"namespace": map[string]interface{}{"id": "ns-min", "name": "tdflite.local"},
			})
		case strings.HasSuffix(path, "/CreateAttribute"):
			json.NewEncoder(w).Encode(map[string]interface{}{
				"attribute": map[string]interface{}{
					"id":     "attr-level",
					"values": []interface{}{map[string]interface{}{"id": "val-basic", "value": "basic"}},
				},
			})
		case strings.HasSuffix(path, "/CreateSubjectMapping"):
			smCount++
			json.NewEncoder(w).Encode(map[string]interface{}{})
		default:
			http.Error(w, "not found", 404)
		}
	}))
	defer server.Close()

	if err := provision.Provision(context.Background(), &loaded, server.URL, "test-token"); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if smCount != 1 {
		t.Errorf("expected 1 subject mapping, got %d", smCount)
	}
}

// ---------------------------------------------------------------------------
// Test 3: TestUnicodeValues
// Attributes with unicode characters: accented, CJK, emoji, special chars.
// ---------------------------------------------------------------------------

func TestUnicodeValues(t *testing.T) {
	bundle := &policybundle.Bundle{
		Attributes: []policybundle.Attribute{
			{
				Name:   "classification_level",
				Rule:   policybundle.RuleHierarchy,
				Values: []string{"Tr\u00e8s Secret", "\u6a5f\u5bc6", "Geheim", "\u0421\u0435\u043a\u0440\u0435\u0442\u043d\u043e"},
			},
			{
				Name:   "region",
				Rule:   policybundle.RuleAnyOf,
				Values: []string{"\u00c9l\u00e9gant", "Stra\u00dfe", "caf\u00e9"},
			},
		},
		Identities: map[string]policybundle.Identity{
			"agent_alpha": {
				Claims: map[string]interface{}{
					"classification_level": "Tr\u00e8s Secret",
					"region":               []string{"\u00c9l\u00e9gant", "caf\u00e9"},
				},
			},
			"agent_beta": {
				Claims: map[string]interface{}{
					"classification_level": "\u6a5f\u5bc6",
					"region":               []string{"Stra\u00dfe"},
				},
			},
			"agent_gamma": {
				Claims: map[string]interface{}{
					"classification_level": "\u0421\u0435\u043a\u0440\u0435\u0442\u043d\u043e",
					"region":               []string{"\u00c9l\u00e9gant"},
				},
			},
		},
	}

	if err := bundle.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	// Seal + sign + round-trip.
	passphrase := "unicode-test"
	if err := policybundle.SealWithPassphrase(bundle, passphrase); err != nil {
		t.Fatalf("SealWithPassphrase: %v", err)
	}
	if err := policybundle.SignBundlePassphrase(bundle); err != nil {
		t.Fatalf("SignBundlePassphrase: %v", err)
	}

	data, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var loaded policybundle.Bundle
	if err := json.Unmarshal(data, &loaded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if err := policybundle.VerifyPassphraseSignature(&loaded); err != nil {
		t.Fatalf("VerifyPassphraseSignature: %v", err)
	}

	keys, err := policybundle.UnsealWithPassphrase(&loaded, passphrase)
	if err != nil {
		t.Fatalf("UnsealWithPassphrase: %v", err)
	}
	if keys.RSAPrivate == nil {
		t.Fatal("keys nil after unseal")
	}

	// Verify values survive round-trip exactly.
	if len(loaded.Attributes) != 2 {
		t.Fatalf("expected 2 attributes, got %d", len(loaded.Attributes))
	}

	expectedVals := map[string][]string{
		"classification_level": {"Tr\u00e8s Secret", "\u6a5f\u5bc6", "Geheim", "\u0421\u0435\u043a\u0440\u0435\u0442\u043d\u043e"},
		"region":               {"\u00c9l\u00e9gant", "Stra\u00dfe", "caf\u00e9"},
	}
	for _, attr := range loaded.Attributes {
		expected, ok := expectedVals[attr.Name]
		if !ok {
			t.Errorf("unexpected attribute %q", attr.Name)
			continue
		}
		if len(attr.Values) != len(expected) {
			t.Errorf("attribute %q: expected %d values, got %d", attr.Name, len(expected), len(attr.Values))
			continue
		}
		for i, v := range attr.Values {
			if v != expected[i] {
				t.Errorf("attribute %q value[%d]: expected %q, got %q", attr.Name, i, expected[i], v)
			}
		}
	}

	// Verify identity claims.
	alpha := loaded.Identities["agent_alpha"]
	if alpha.Claims["classification_level"] != "Tr\u00e8s Secret" {
		t.Errorf("agent_alpha classification: expected 'Tr\u00e8s Secret', got %v", alpha.Claims["classification_level"])
	}
	beta := loaded.Identities["agent_beta"]
	if beta.Claims["classification_level"] != "\u6a5f\u5bc6" {
		t.Errorf("agent_beta classification: expected '\u6a5f\u5bc6', got %v", beta.Claims["classification_level"])
	}

	// GenerateIdentities should work.
	output, err := policybundle.GenerateIdentities(&loaded)
	if err != nil {
		t.Fatalf("GenerateIdentities: %v", err)
	}
	if len(output.Users) != 3 {
		t.Errorf("expected 3 users, got %d", len(output.Users))
	}
}

// ---------------------------------------------------------------------------
// Test 4: TestLongValues
// Attribute with very long value strings (1000 chars).
// Identity with many claims (10+ attributes).
// ---------------------------------------------------------------------------

func TestLongValues(t *testing.T) {
	// Create a 1000-character value.
	longVal := strings.Repeat("abcdefghij", 100)
	if len(longVal) != 1000 {
		t.Fatalf("expected 1000-char string, got %d", len(longVal))
	}

	// Create 12 attributes (to test identity with many claims).
	attrs := make([]policybundle.Attribute, 12)
	claims := make(map[string]interface{})
	for i := 0; i < 12; i++ {
		name := fmt.Sprintf("attr_%02d", i)
		val := fmt.Sprintf("%s_%d", longVal, i)
		attrs[i] = policybundle.Attribute{
			Name:   name,
			Rule:   policybundle.RuleHierarchy,
			Values: []string{val, "short"},
		}
		claims[name] = val
	}

	bundle := &policybundle.Bundle{
		Attributes: attrs,
		Identities: map[string]policybundle.Identity{
			"longuser": {Claims: claims},
		},
	}

	if err := bundle.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	// Seal + unseal round-trip.
	passphrase := "long-values-test"
	if err := policybundle.SealWithPassphrase(bundle, passphrase); err != nil {
		t.Fatalf("SealWithPassphrase: %v", err)
	}
	if err := policybundle.SignBundlePassphrase(bundle); err != nil {
		t.Fatalf("SignBundlePassphrase: %v", err)
	}

	data, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var loaded policybundle.Bundle
	if err := json.Unmarshal(data, &loaded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if err := policybundle.VerifyPassphraseSignature(&loaded); err != nil {
		t.Fatalf("VerifyPassphraseSignature: %v", err)
	}

	keys, err := policybundle.UnsealWithPassphrase(&loaded, passphrase)
	if err != nil {
		t.Fatalf("UnsealWithPassphrase: %v", err)
	}
	if keys.RSAPrivate == nil {
		t.Fatal("keys nil after unseal")
	}

	// Verify all 12 long values survive round-trip.
	for i := 0; i < 12; i++ {
		name := fmt.Sprintf("attr_%02d", i)
		expectedVal := fmt.Sprintf("%s_%d", longVal, i)

		attr := loaded.Attributes[i]
		if attr.Values[0] != expectedVal {
			t.Errorf("attribute %q: value did not survive round-trip (len expected %d, got %d)", name, len(expectedVal), len(attr.Values[0]))
		}

		// Verify claim preserved.
		user := loaded.Identities["longuser"]
		if user.Claims[name] != expectedVal {
			t.Errorf("identity claim %q: value did not survive round-trip", name)
		}
	}

	// Verify identity generation works with many claims.
	output, err := policybundle.GenerateIdentities(&loaded)
	if err != nil {
		t.Fatalf("GenerateIdentities: %v", err)
	}
	if len(output.Users) != 1 {
		t.Errorf("expected 1 user, got %d", len(output.Users))
	}
	if len(output.Users[0].CustomClaims) != 12 {
		t.Errorf("expected 12 custom claims, got %d", len(output.Users[0].CustomClaims))
	}
}

// ---------------------------------------------------------------------------
// Test 5: TestSpecialCharactersInCredentials
// Identity with special characters in password, client_id, client_secret.
// ---------------------------------------------------------------------------

func TestSpecialCharactersInCredentials(t *testing.T) {
	bundle := &policybundle.Bundle{
		Attributes: []policybundle.Attribute{
			{Name: "tier", Rule: policybundle.RuleHierarchy, Values: []string{"gold", "silver"}},
		},
		Identities: map[string]policybundle.Identity{
			"specialuser": {
				Claims:       map[string]interface{}{"tier": "gold"},
				Password:     `p@$$w0rd!#%^&*(){}[]`,
				ClientID:     "my-app.v2.prod",
				ClientSecret: "abc123+/=",
			},
		},
	}

	if err := bundle.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	// Seal + sign + round-trip + unseal.
	pubPath, privPath := generateSSHKeyPair(t)
	if err := policybundle.SealWithSSHKey(bundle, pubPath); err != nil {
		t.Fatalf("SealWithSSHKey: %v", err)
	}
	if err := policybundle.SignBundle(bundle, privPath); err != nil {
		t.Fatalf("SignBundle: %v", err)
	}

	data, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var loaded policybundle.Bundle
	if err := json.Unmarshal(data, &loaded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if err := policybundle.VerifySignature(&loaded, pubPath); err != nil {
		t.Fatalf("VerifySignature: %v", err)
	}

	keys, err := policybundle.UnsealWithSSHKey(&loaded, privPath)
	if err != nil {
		t.Fatalf("UnsealWithSSHKey: %v", err)
	}
	if keys.RSAPrivate == nil {
		t.Fatal("keys nil after unseal")
	}

	// Verify credentials survive round-trip.
	user := loaded.Identities["specialuser"]
	if user.Password != `p@$$w0rd!#%^&*(){}[]` {
		t.Errorf("password mismatch: got %q", user.Password)
	}
	if user.ClientID != "my-app.v2.prod" {
		t.Errorf("client_id mismatch: got %q", user.ClientID)
	}
	if user.ClientSecret != "abc123+/=" {
		t.Errorf("client_secret mismatch: got %q", user.ClientSecret)
	}

	// GenerateIdentities should use the custom credentials.
	output, err := policybundle.GenerateIdentities(&loaded)
	if err != nil {
		t.Fatalf("GenerateIdentities: %v", err)
	}
	if len(output.Users) != 1 {
		t.Fatalf("expected 1 user, got %d", len(output.Users))
	}
	u := output.Users[0]
	if u.Password != `p@$$w0rd!#%^&*(){}[]` {
		t.Errorf("generated identity password: got %q", u.Password)
	}
	if u.ClientID != "my-app.v2.prod" {
		t.Errorf("generated identity client_id: got %q", u.ClientID)
	}
	if u.ClientSecret != "abc123+/=" {
		t.Errorf("generated identity client_secret: got %q", u.ClientSecret)
	}
}

// ---------------------------------------------------------------------------
// Test 6: TestMultipleSealUnsealCycles
// Seal a bundle, unseal, re-seal, unseal again.
// Verify keys are DIFFERENT between seals (fresh key generation).
// But the policy content is identical.
// ---------------------------------------------------------------------------

func TestMultipleSealUnsealCycles(t *testing.T) {
	bundle := &policybundle.Bundle{
		Attributes: []policybundle.Attribute{
			{Name: "env", Rule: policybundle.RuleHierarchy, Values: []string{"prod", "staging", "dev"}},
		},
		Identities: map[string]policybundle.Identity{
			"deployer": {Claims: map[string]interface{}{"env": "prod"}},
		},
	}

	if err := bundle.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	passphrase := "multi-cycle"

	// First seal + unseal.
	if err := policybundle.SealWithPassphrase(bundle, passphrase); err != nil {
		t.Fatalf("first SealWithPassphrase: %v", err)
	}
	if err := policybundle.SignBundlePassphrase(bundle); err != nil {
		t.Fatalf("first SignBundlePassphrase: %v", err)
	}

	data1, _ := json.Marshal(bundle)
	var loaded1 policybundle.Bundle
	json.Unmarshal(data1, &loaded1)

	keys1, err := policybundle.UnsealWithPassphrase(&loaded1, passphrase)
	if err != nil {
		t.Fatalf("first UnsealWithPassphrase: %v", err)
	}

	// Get RSA modulus from first seal for comparison.
	rsaMod1 := keys1.RSAPrivate.N.Bytes()
	ecX1 := keys1.ECPrivate.X.Bytes()

	// Second seal: clear sealed data and re-seal.
	bundle.Sealed = nil
	bundle.Signature = ""

	if err := policybundle.SealWithPassphrase(bundle, passphrase); err != nil {
		t.Fatalf("second SealWithPassphrase: %v", err)
	}
	if err := policybundle.SignBundlePassphrase(bundle); err != nil {
		t.Fatalf("second SignBundlePassphrase: %v", err)
	}

	data2, _ := json.Marshal(bundle)
	var loaded2 policybundle.Bundle
	json.Unmarshal(data2, &loaded2)

	keys2, err := policybundle.UnsealWithPassphrase(&loaded2, passphrase)
	if err != nil {
		t.Fatalf("second UnsealWithPassphrase: %v", err)
	}

	rsaMod2 := keys2.RSAPrivate.N.Bytes()
	ecX2 := keys2.ECPrivate.X.Bytes()

	// Keys MUST be different (fresh generation).
	if string(rsaMod1) == string(rsaMod2) {
		t.Error("RSA keys are identical across seals — expected fresh generation")
	}
	if string(ecX1) == string(ecX2) {
		t.Error("EC keys are identical across seals — expected fresh generation")
	}

	// But policy content must be identical.
	if len(loaded1.Attributes) != len(loaded2.Attributes) {
		t.Error("attribute count mismatch between seals")
	}
	if loaded1.Attributes[0].Name != loaded2.Attributes[0].Name {
		t.Error("attribute name mismatch between seals")
	}
	if len(loaded1.Identities) != len(loaded2.Identities) {
		t.Error("identity count mismatch between seals")
	}
}

// ---------------------------------------------------------------------------
// Test 7: TestRebindPreservesKeys
// Seal with key A, rebind to key B, unseal with B.
// Verify KAS keys are identical (same key material, different encryption wrapper).
// ---------------------------------------------------------------------------

func TestRebindPreservesKeys(t *testing.T) {
	bundle := &policybundle.Bundle{
		Attributes: []policybundle.Attribute{
			{Name: "access", Rule: policybundle.RuleAnyOf, Values: []string{"read", "write", "admin"}},
		},
		Identities: map[string]policybundle.Identity{
			"rebinduser": {Claims: map[string]interface{}{"access": []string{"read", "write"}}},
		},
	}

	if err := bundle.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	// Generate two SSH key pairs.
	pubA, privA := generateSSHKeyPair(t)
	pubB, privB := generateSSHKeyPair(t)

	// Seal with key A.
	if err := policybundle.SealWithSSHKey(bundle, pubA); err != nil {
		t.Fatalf("SealWithSSHKey(A): %v", err)
	}
	if err := policybundle.SignBundle(bundle, privA); err != nil {
		t.Fatalf("SignBundle(A): %v", err)
	}

	// Unseal with A to get original keys.
	keysA, err := policybundle.UnsealWithSSHKey(bundle, privA)
	if err != nil {
		t.Fatalf("UnsealWithSSHKey(A): %v", err)
	}

	// Rebind to key B.
	if err := policybundle.RebindSSHKey(bundle, privA, privB); err != nil {
		t.Fatalf("RebindSSHKey: %v", err)
	}

	// Verify the bundle is sealed with key B's fingerprint.
	if err := policybundle.VerifySignature(bundle, pubB); err != nil {
		t.Fatalf("VerifySignature(B) after rebind: %v", err)
	}

	// Unseal with B.
	keysB, err := policybundle.UnsealWithSSHKey(bundle, privB)
	if err != nil {
		t.Fatalf("UnsealWithSSHKey(B) after rebind: %v", err)
	}

	// Verify KAS keys are identical: same RSA modulus, same EC curve point.
	if keysA.RSAPrivate.N.Cmp(keysB.RSAPrivate.N) != 0 {
		t.Error("RSA modulus differs after rebind — expected identical key material")
	}
	if keysA.RSAPrivate.D.Cmp(keysB.RSAPrivate.D) != 0 {
		t.Error("RSA private exponent differs after rebind")
	}
	if keysA.ECPrivate.X.Cmp(keysB.ECPrivate.X) != 0 || keysA.ECPrivate.Y.Cmp(keysB.ECPrivate.Y) != 0 {
		t.Error("EC public key differs after rebind")
	}
	if keysA.ECPrivate.D.Cmp(keysB.ECPrivate.D) != 0 {
		t.Error("EC private key differs after rebind")
	}
	if keysA.IDPKey.N.Cmp(keysB.IDPKey.N) != 0 {
		t.Error("IDP key modulus differs after rebind")
	}

	// Verify certs are the same (rebind re-serializes from parsed keys, certs should match).
	rsaCertA, _ := pem.Decode(keysA.RSACert)
	rsaCertB, _ := pem.Decode(keysB.RSACert)
	certA, _ := x509.ParseCertificate(rsaCertA.Bytes)
	certB, _ := x509.ParseCertificate(rsaCertB.Bytes)
	if certA.SerialNumber.Cmp(certB.SerialNumber) != 0 {
		t.Error("RSA cert serial number differs after rebind")
	}
}

// ---------------------------------------------------------------------------
// Test 8: TestAllRuleTypeCombinations
// Identity with every possible combination of rule types.
// ---------------------------------------------------------------------------

func TestAllRuleTypeCombinations(t *testing.T) {
	bundle := &policybundle.Bundle{
		Attributes: []policybundle.Attribute{
			{Name: "clearance", Rule: policybundle.RuleHierarchy, Values: []string{"high", "medium", "low"}},
			{Name: "projects", Rule: policybundle.RuleAllOf, Values: []string{"alpha", "beta", "gamma"}},
			{Name: "regions", Rule: policybundle.RuleAnyOf, Values: []string{"east", "west", "central"}},
		},
		Identities: map[string]policybundle.Identity{
			// Only hierarchy
			"hier_only": {Claims: map[string]interface{}{"clearance": "high"}},
			// Only allOf
			"allof_only": {Claims: map[string]interface{}{"projects": []string{"alpha", "beta"}}},
			// Only anyOf
			"anyof_only": {Claims: map[string]interface{}{"regions": []string{"east"}}},
			// hierarchy + allOf
			"hier_allof": {Claims: map[string]interface{}{
				"clearance": "medium",
				"projects":  []string{"alpha"},
			}},
			// hierarchy + anyOf
			"hier_anyof": {Claims: map[string]interface{}{
				"clearance": "low",
				"regions":   []string{"west", "central"},
			}},
			// allOf + anyOf
			"allof_anyof": {Claims: map[string]interface{}{
				"projects": []string{"alpha", "beta", "gamma"},
				"regions":  []string{"east", "west"},
			}},
			// All three
			"all_three": {Claims: map[string]interface{}{
				"clearance": "high",
				"projects":  []string{"alpha", "beta"},
				"regions":   []string{"east", "west", "central"},
			}},
			// No claims (admin only)
			"admin_only": {Claims: map[string]interface{}{}, Admin: true},
		},
	}

	if err := bundle.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	// Full pipeline for each identity.
	passphrase := "all-rules-test"
	if err := policybundle.SealWithPassphrase(bundle, passphrase); err != nil {
		t.Fatalf("SealWithPassphrase: %v", err)
	}
	if err := policybundle.SignBundlePassphrase(bundle); err != nil {
		t.Fatalf("SignBundlePassphrase: %v", err)
	}

	data, _ := json.Marshal(bundle)
	var loaded policybundle.Bundle
	if err := json.Unmarshal(data, &loaded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if err := policybundle.VerifyPassphraseSignature(&loaded); err != nil {
		t.Fatalf("VerifyPassphraseSignature: %v", err)
	}

	keys, err := policybundle.UnsealWithPassphrase(&loaded, passphrase)
	if err != nil {
		t.Fatalf("UnsealWithPassphrase: %v", err)
	}
	if keys.RSAPrivate == nil {
		t.Fatal("keys nil")
	}

	output, err := policybundle.GenerateIdentities(&loaded)
	if err != nil {
		t.Fatalf("GenerateIdentities: %v", err)
	}

	if len(output.Users) != 8 {
		t.Fatalf("expected 8 users, got %d", len(output.Users))
	}

	// Verify specific identity claims.
	usersByName := make(map[string]struct{ Claims map[string]any })
	for _, u := range output.Users {
		usersByName[u.Username] = struct{ Claims map[string]any }{u.CustomClaims}
	}

	// hier_only should only have clearance.
	hierOnly := usersByName["hier_only"]
	if len(hierOnly.Claims) != 1 {
		t.Errorf("hier_only: expected 1 claim, got %d", len(hierOnly.Claims))
	}

	// admin_only should have no custom claims (or empty map).
	adminOnly := usersByName["admin_only"]
	if len(adminOnly.Claims) != 0 {
		t.Errorf("admin_only: expected 0 claims, got %d", len(adminOnly.Claims))
	}

	// all_three should have 3 claims.
	allThree := usersByName["all_three"]
	if len(allThree.Claims) != 3 {
		t.Errorf("all_three: expected 3 claims, got %d", len(allThree.Claims))
	}
}

// ---------------------------------------------------------------------------
// Test 9: TestDeterministicOutput
// Two identical bundles sealed separately should produce different keys but identical policy.
// ---------------------------------------------------------------------------

func TestDeterministicOutput(t *testing.T) {
	makeBundle := func() *policybundle.Bundle {
		return &policybundle.Bundle{
			Attributes: []policybundle.Attribute{
				{Name: "color", Rule: policybundle.RuleAnyOf, Values: []string{"red", "blue", "green"}},
			},
			Identities: map[string]policybundle.Identity{
				"painter": {Claims: map[string]interface{}{"color": []string{"red", "blue"}}},
			},
		}
	}

	pubPath, privPath := generateSSHKeyPair(t)

	bundle1 := makeBundle()
	if err := policybundle.SealWithSSHKey(bundle1, pubPath); err != nil {
		t.Fatalf("seal bundle1: %v", err)
	}
	if err := policybundle.SignBundle(bundle1, privPath); err != nil {
		t.Fatalf("sign bundle1: %v", err)
	}

	bundle2 := makeBundle()
	if err := policybundle.SealWithSSHKey(bundle2, pubPath); err != nil {
		t.Fatalf("seal bundle2: %v", err)
	}
	if err := policybundle.SignBundle(bundle2, privPath); err != nil {
		t.Fatalf("sign bundle2: %v", err)
	}

	// Signatures should be DIFFERENT (different sealed key material in canonical bytes).
	if bundle1.Signature == bundle2.Signature {
		t.Error("signatures are identical — expected different due to random key generation")
	}

	// Encrypted KAS keys should be different.
	if bundle1.Sealed.KASKeys == bundle2.Sealed.KASKeys {
		t.Error("encrypted KAS keys are identical — expected different")
	}

	// But the policy content should be identical.
	if len(bundle1.Attributes) != len(bundle2.Attributes) {
		t.Error("attribute count differs")
	}
	if bundle1.Attributes[0].Name != bundle2.Attributes[0].Name {
		t.Error("attribute names differ")
	}

	// Unseal both — keys should be different.
	keys1, err := policybundle.UnsealWithSSHKey(bundle1, privPath)
	if err != nil {
		t.Fatalf("unseal bundle1: %v", err)
	}
	keys2, err := policybundle.UnsealWithSSHKey(bundle2, privPath)
	if err != nil {
		t.Fatalf("unseal bundle2: %v", err)
	}

	if keys1.RSAPrivate.N.Cmp(keys2.RSAPrivate.N) == 0 {
		t.Error("RSA keys are identical between seals — expected different")
	}
	if keys1.ECPrivate.D.Cmp(keys2.ECPrivate.D) == 0 {
		t.Error("EC keys are identical between seals — expected different")
	}
}

// ---------------------------------------------------------------------------
// Test 10: TestConcurrentSealUnseal
// 10 bundles sealed/unsealed in parallel goroutines. All must succeed.
// ---------------------------------------------------------------------------

func TestConcurrentSealUnseal(t *testing.T) {
	pubPath, privPath := generateSSHKeyPair(t)

	var wg sync.WaitGroup
	errors := make([]error, 10)

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			b := &policybundle.Bundle{
				Attributes: []policybundle.Attribute{
					{Name: fmt.Sprintf("attr_%d", idx), Rule: policybundle.RuleHierarchy, Values: []string{"a", "b", "c"}},
				},
				Identities: map[string]policybundle.Identity{
					fmt.Sprintf("user_%d", idx): {Claims: map[string]interface{}{fmt.Sprintf("attr_%d", idx): "a"}},
				},
			}

			if err := b.Validate(); err != nil {
				errors[idx] = fmt.Errorf("validate: %w", err)
				return
			}

			if err := policybundle.SealWithSSHKey(b, pubPath); err != nil {
				errors[idx] = fmt.Errorf("seal: %w", err)
				return
			}
			if err := policybundle.SignBundle(b, privPath); err != nil {
				errors[idx] = fmt.Errorf("sign: %w", err)
				return
			}

			// Round-trip.
			data, err := json.Marshal(b)
			if err != nil {
				errors[idx] = fmt.Errorf("marshal: %w", err)
				return
			}

			var loaded policybundle.Bundle
			if err := json.Unmarshal(data, &loaded); err != nil {
				errors[idx] = fmt.Errorf("unmarshal: %w", err)
				return
			}

			if err := policybundle.VerifySignature(&loaded, pubPath); err != nil {
				errors[idx] = fmt.Errorf("verify: %w", err)
				return
			}

			keys, err := policybundle.UnsealWithSSHKey(&loaded, privPath)
			if err != nil {
				errors[idx] = fmt.Errorf("unseal: %w", err)
				return
			}

			if keys.RSAPrivate == nil || keys.ECPrivate == nil || keys.IDPKey == nil {
				errors[idx] = fmt.Errorf("nil keys after unseal")
				return
			}
		}(i)
	}

	wg.Wait()

	for i, err := range errors {
		if err != nil {
			t.Errorf("goroutine %d: %v", i, err)
		}
	}
}

// ---------------------------------------------------------------------------
// Test 11: TestEveryIdentityClaimCombination
// For a bundle with 3 attributes (hierarchy + allOf + anyOf), create identities
// testing every meaningful claim subset.
// ---------------------------------------------------------------------------

func TestEveryIdentityClaimCombination(t *testing.T) {
	bundle := &policybundle.Bundle{
		Attributes: []policybundle.Attribute{
			{Name: "rank", Rule: policybundle.RuleHierarchy, Values: []string{"general", "colonel", "private"}},
			{Name: "skills", Rule: policybundle.RuleAllOf, Values: []string{"ops", "intel", "logistics", "cyber"}},
			{Name: "theaters", Rule: policybundle.RuleAnyOf, Values: []string{"pacific", "atlantic", "arctic"}},
		},
		Identities: map[string]policybundle.Identity{
			// All claims present, full arrays.
			"full": {Claims: map[string]interface{}{
				"rank":     "general",
				"skills":   []string{"ops", "intel", "logistics", "cyber"},
				"theaters": []string{"pacific", "atlantic", "arctic"},
			}},
			// Only required (hierarchy only).
			"rank_only": {Claims: map[string]interface{}{
				"rank": "colonel",
			}},
			// Missing hierarchy, only allOf.
			"skills_only": {Claims: map[string]interface{}{
				"skills": []string{"ops"},
			}},
			// Missing hierarchy, only anyOf.
			"theaters_only": {Claims: map[string]interface{}{
				"theaters": []string{"pacific"},
			}},
			// Single-element arrays for allOf/anyOf.
			"single_elements": {Claims: map[string]interface{}{
				"rank":     "private",
				"skills":   []string{"cyber"},
				"theaters": []string{"arctic"},
			}},
			// Full arrays, low hierarchy.
			"full_low": {Claims: map[string]interface{}{
				"rank":     "private",
				"skills":   []string{"ops", "intel", "logistics", "cyber"},
				"theaters": []string{"pacific", "atlantic", "arctic"},
			}},
			// Hierarchy + allOf only (no anyOf).
			"rank_skills": {Claims: map[string]interface{}{
				"rank":   "general",
				"skills": []string{"ops", "intel"},
			}},
			// Hierarchy + anyOf only (no allOf).
			"rank_theaters": {Claims: map[string]interface{}{
				"rank":     "colonel",
				"theaters": []string{"atlantic", "arctic"},
			}},
			// allOf + anyOf only (no hierarchy).
			"skills_theaters": {Claims: map[string]interface{}{
				"skills":   []string{"ops", "logistics"},
				"theaters": []string{"pacific"},
			}},
			// Admin with no claims.
			"admin_noclaims": {Claims: map[string]interface{}{}, Admin: true},
		},
	}

	if err := bundle.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	// Full pipeline.
	passphrase := "every-claim-combo"
	if err := policybundle.SealWithPassphrase(bundle, passphrase); err != nil {
		t.Fatalf("SealWithPassphrase: %v", err)
	}
	if err := policybundle.SignBundlePassphrase(bundle); err != nil {
		t.Fatalf("SignBundlePassphrase: %v", err)
	}

	data, _ := json.Marshal(bundle)
	var loaded policybundle.Bundle
	if err := json.Unmarshal(data, &loaded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if err := policybundle.VerifyPassphraseSignature(&loaded); err != nil {
		t.Fatalf("VerifyPassphraseSignature: %v", err)
	}

	keys, err := policybundle.UnsealWithPassphrase(&loaded, passphrase)
	if err != nil {
		t.Fatalf("UnsealWithPassphrase: %v", err)
	}
	if keys.RSAPrivate == nil {
		t.Fatal("keys nil")
	}

	output, err := policybundle.GenerateIdentities(&loaded)
	if err != nil {
		t.Fatalf("GenerateIdentities: %v", err)
	}

	if len(output.Users) != 10 {
		t.Fatalf("expected 10 users, got %d", len(output.Users))
	}

	// Build lookup.
	byName := make(map[string]map[string]any)
	var adminFound bool
	for _, u := range output.Users {
		byName[u.Username] = u.CustomClaims
		if u.Username == "admin_noclaims" {
			adminFound = true
			// Admin should have admin roles.
			hasAdmin := false
			for _, r := range u.Roles {
				if r == "opentdf-admin" {
					hasAdmin = true
				}
			}
			if !hasAdmin {
				t.Error("admin_noclaims should have opentdf-admin role")
			}
		}
	}
	if !adminFound {
		t.Error("admin_noclaims user not found in output")
	}

	// Verify "full" user has all 3 claims.
	fullClaims := byName["full"]
	if len(fullClaims) != 3 {
		t.Errorf("full: expected 3 claims, got %d", len(fullClaims))
	}

	// Verify "rank_only" has exactly 1 claim.
	rankOnlyClaims := byName["rank_only"]
	if len(rankOnlyClaims) != 1 {
		t.Errorf("rank_only: expected 1 claim, got %d", len(rankOnlyClaims))
	}

	// Verify "admin_noclaims" has 0 claims.
	adminClaims := byName["admin_noclaims"]
	if len(adminClaims) != 0 {
		t.Errorf("admin_noclaims: expected 0 claims, got %d", len(adminClaims))
	}

	// Verify "single_elements" has all 3 claims with single values.
	singleClaims := byName["single_elements"]
	if len(singleClaims) != 3 {
		t.Errorf("single_elements: expected 3 claims, got %d", len(singleClaims))
	}
	if singleClaims["rank"] != "private" {
		t.Errorf("single_elements rank: expected 'private', got %v", singleClaims["rank"])
	}
}
