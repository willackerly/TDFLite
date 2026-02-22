package tests_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/willackerly/TDFLite/internal/policybundle"
	"github.com/willackerly/TDFLite/internal/provision"
)

// ---------------------------------------------------------------------------
// Test 1: TestCustomNamespacePropagation
// ---------------------------------------------------------------------------

func TestCustomNamespacePropagation(t *testing.T) {
	bundle := &policybundle.Bundle{
		Namespace: "classified.gov",
		Attributes: []policybundle.Attribute{
			{Name: "level", Rule: policybundle.RuleHierarchy, Values: []string{"high", "low"}},
		},
		Identities: map[string]policybundle.Identity{
			"user1": {Claims: map[string]interface{}{"level": "high"}},
		},
	}

	if err := bundle.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	pubPath, privPath := generateSSHKeyPair(t)

	// Seal + sign.
	if err := policybundle.SealWithSSHKey(bundle, pubPath); err != nil {
		t.Fatalf("SealWithSSHKey: %v", err)
	}
	if err := policybundle.SignBundle(bundle, privPath); err != nil {
		t.Fatalf("SignBundle: %v", err)
	}

	// Round-trip through JSON.
	data, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var loaded policybundle.Bundle
	if err := json.Unmarshal(data, &loaded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// Verify namespace preserved.
	if loaded.Namespace != "classified.gov" {
		t.Errorf("expected Namespace %q, got %q", "classified.gov", loaded.Namespace)
	}
	if loaded.EffectiveNamespace() != "classified.gov" {
		t.Errorf("expected EffectiveNamespace %q, got %q", "classified.gov", loaded.EffectiveNamespace())
	}

	// Provision against mock and verify namespace.
	var mu sync.Mutex
	var requests []requestRecord

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, _ := io.ReadAll(r.Body)
		defer r.Body.Close()

		var bodyMap map[string]interface{}
		json.Unmarshal(bodyBytes, &bodyMap)

		mu.Lock()
		requests = append(requests, requestRecord{
			Method: r.Method,
			Path:   r.URL.Path,
			Body:   bodyMap,
		})
		mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		path := r.URL.Path
		switch {
		case strings.HasSuffix(path, "/CreateNamespace"):
			json.NewEncoder(w).Encode(map[string]interface{}{
				"namespace": map[string]interface{}{"id": "ns-custom", "name": "classified.gov"},
			})
		case strings.HasSuffix(path, "/CreateAttribute"):
			json.NewEncoder(w).Encode(map[string]interface{}{
				"attribute": map[string]interface{}{
					"id": "attr-1",
					"values": []interface{}{
						map[string]interface{}{"id": "val-1", "value": "high"},
						map[string]interface{}{"id": "val-2", "value": "low"},
					},
				},
			})
		case strings.HasSuffix(path, "/CreateSubjectMapping"):
			json.NewEncoder(w).Encode(map[string]interface{}{})
		default:
			http.Error(w, "not found", 404)
		}
	}))
	defer server.Close()

	ctx := context.Background()
	if err := provision.Provision(ctx, &loaded, server.URL, "test-token"); err != nil {
		t.Fatalf("Provision: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()

	// Find the CreateNamespace request and verify it used "classified.gov".
	found := false
	for _, req := range requests {
		if strings.HasSuffix(req.Path, "/CreateNamespace") {
			found = true
			nsName, _ := req.Body["name"].(string)
			if nsName != "classified.gov" {
				t.Errorf("CreateNamespace used namespace %q, expected %q", nsName, "classified.gov")
			}
		}
	}
	if !found {
		t.Fatal("no CreateNamespace request found")
	}
}

// ---------------------------------------------------------------------------
// Test 2: TestCustomCredentialsPropagation
// ---------------------------------------------------------------------------

func TestCustomCredentialsPropagation(t *testing.T) {
	bundle := &policybundle.Bundle{
		Attributes: []policybundle.Attribute{
			{Name: "level", Rule: policybundle.RuleHierarchy, Values: []string{"high", "low"}},
		},
		Identities: map[string]policybundle.Identity{
			"alice": {
				Claims:       map[string]interface{}{"level": "high"},
				Password:     "alice-pw-123",
				ClientID:     "alice-app",
				ClientSecret: "alice-app-s3cret",
			},
			"bob": {
				Claims: map[string]interface{}{"level": "low"},
				// All defaults — no overrides.
			},
			"carol": {
				Claims:   map[string]interface{}{"level": "high"},
				Password: "carol-custom",
				// Only password overridden, client_id and client_secret default.
			},
		},
	}

	if err := bundle.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	pubPath, privPath := generateSSHKeyPair(t)

	// Seal + sign.
	if err := policybundle.SealWithSSHKey(bundle, pubPath); err != nil {
		t.Fatalf("SealWithSSHKey: %v", err)
	}
	if err := policybundle.SignBundle(bundle, privPath); err != nil {
		t.Fatalf("SignBundle: %v", err)
	}

	// Round-trip through JSON.
	data, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var loaded policybundle.Bundle
	if err := json.Unmarshal(data, &loaded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// Verify credentials survived serialization at the bundle level.
	aliceBundle := loaded.Identities["alice"]
	if aliceBundle.Password != "alice-pw-123" {
		t.Errorf("alice password after round-trip: expected %q, got %q", "alice-pw-123", aliceBundle.Password)
	}
	if aliceBundle.ClientID != "alice-app" {
		t.Errorf("alice client_id after round-trip: expected %q, got %q", "alice-app", aliceBundle.ClientID)
	}
	if aliceBundle.ClientSecret != "alice-app-s3cret" {
		t.Errorf("alice client_secret after round-trip: expected %q, got %q", "alice-app-s3cret", aliceBundle.ClientSecret)
	}

	carolBundle := loaded.Identities["carol"]
	if carolBundle.Password != "carol-custom" {
		t.Errorf("carol password after round-trip: expected %q, got %q", "carol-custom", carolBundle.Password)
	}
	if carolBundle.ClientID != "" {
		t.Errorf("carol client_id should be empty (default), got %q", carolBundle.ClientID)
	}
	if carolBundle.ClientSecret != "" {
		t.Errorf("carol client_secret should be empty (default), got %q", carolBundle.ClientSecret)
	}

	// GenerateIdentities from the round-tripped bundle.
	output, err := policybundle.GenerateIdentities(&loaded)
	if err != nil {
		t.Fatalf("GenerateIdentities: %v", err)
	}

	usersByName := make(map[string]struct {
		ClientID     string
		ClientSecret string
		Password     string
	})
	for _, u := range output.Users {
		usersByName[u.Username] = struct {
			ClientID     string
			ClientSecret string
			Password     string
		}{u.ClientID, u.ClientSecret, u.Password}
	}

	// Alice: all custom.
	alice := usersByName["alice"]
	if alice.Password != "alice-pw-123" {
		t.Errorf("alice generated password: expected %q, got %q", "alice-pw-123", alice.Password)
	}
	if alice.ClientID != "alice-app" {
		t.Errorf("alice generated client_id: expected %q, got %q", "alice-app", alice.ClientID)
	}
	if alice.ClientSecret != "alice-app-s3cret" {
		t.Errorf("alice generated client_secret: expected %q, got %q", "alice-app-s3cret", alice.ClientSecret)
	}

	// Bob: all defaults.
	bob := usersByName["bob"]
	if bob.Password != "bob-secret" {
		t.Errorf("bob generated password: expected %q, got %q", "bob-secret", bob.Password)
	}
	if bob.ClientID != "bob-client" {
		t.Errorf("bob generated client_id: expected %q, got %q", "bob-client", bob.ClientID)
	}
	if bob.ClientSecret != "bob-secret" {
		t.Errorf("bob generated client_secret: expected %q, got %q", "bob-secret", bob.ClientSecret)
	}

	// Carol: custom password, default client_id and client_secret.
	carol := usersByName["carol"]
	if carol.Password != "carol-custom" {
		t.Errorf("carol generated password: expected %q, got %q", "carol-custom", carol.Password)
	}
	if carol.ClientID != "carol-client" {
		t.Errorf("carol generated client_id: expected %q, got %q", "carol-client", carol.ClientID)
	}
	if carol.ClientSecret != "carol-secret" {
		t.Errorf("carol generated client_secret: expected %q, got %q", "carol-secret", carol.ClientSecret)
	}
}

// ---------------------------------------------------------------------------
// Test 3: TestAdminRolePropagation
// ---------------------------------------------------------------------------

func TestAdminRolePropagation(t *testing.T) {
	bundle := &policybundle.Bundle{
		Attributes: []policybundle.Attribute{
			{Name: "level", Rule: policybundle.RuleHierarchy, Values: []string{"high", "low"}},
		},
		Identities: map[string]policybundle.Identity{
			"alice": {
				Claims: map[string]interface{}{"level": "high"},
				Admin:  true,
			},
			"bob": {
				Claims: map[string]interface{}{"level": "low"},
				Admin:  false, // explicit false
			},
			"carol": {
				Claims: map[string]interface{}{"level": "low"},
				// Admin not set (implicit false)
			},
		},
	}

	output, err := policybundle.GenerateIdentities(bundle)
	if err != nil {
		t.Fatalf("GenerateIdentities: %v", err)
	}

	usersByName := make(map[string][]string)
	for _, u := range output.Users {
		usersByName[u.Username] = u.Roles
	}

	// Alice: admin=true -> both roles.
	aliceRoles := usersByName["alice"]
	sort.Strings(aliceRoles)
	expectedAdmin := []string{"opentdf-admin", "opentdf-standard"}
	sort.Strings(expectedAdmin)
	if !reflect.DeepEqual(aliceRoles, expectedAdmin) {
		t.Errorf("alice roles: expected %v, got %v", expectedAdmin, aliceRoles)
	}

	// Bob: admin=false -> standard only.
	bobRoles := usersByName["bob"]
	expectedStd := []string{"opentdf-standard"}
	if !reflect.DeepEqual(bobRoles, expectedStd) {
		t.Errorf("bob roles: expected %v, got %v", expectedStd, bobRoles)
	}

	// Carol: admin not set -> standard only.
	carolRoles := usersByName["carol"]
	if !reflect.DeepEqual(carolRoles, expectedStd) {
		t.Errorf("carol roles: expected %v, got %v", expectedStd, carolRoles)
	}
}

// ---------------------------------------------------------------------------
// Test 4: TestCustomActionsPropagation
// ---------------------------------------------------------------------------

func TestCustomActionsPropagation(t *testing.T) {
	bundle := &policybundle.Bundle{
		Attributes: []policybundle.Attribute{
			{Name: "dept", Rule: policybundle.RuleAnyOf, Values: []string{"eng", "sales"}},
		},
		Identities: map[string]policybundle.Identity{
			"user1": {Claims: map[string]interface{}{"dept": []string{"eng"}}},
		},
		Options: &policybundle.Options{
			DefaultActions: []string{"read", "create", "update", "delete"},
		},
	}

	if err := bundle.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	pubPath, privPath := generateSSHKeyPair(t)

	if err := policybundle.SealWithSSHKey(bundle, pubPath); err != nil {
		t.Fatalf("SealWithSSHKey: %v", err)
	}
	if err := policybundle.SignBundle(bundle, privPath); err != nil {
		t.Fatalf("SignBundle: %v", err)
	}

	// Verify EffectiveActions.
	actions := bundle.EffectiveActions()
	expected := []string{"read", "create", "update", "delete"}
	if !reflect.DeepEqual(actions, expected) {
		t.Errorf("EffectiveActions: expected %v, got %v", expected, actions)
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

	// Verify actions survive round-trip.
	loadedActions := loaded.EffectiveActions()
	if !reflect.DeepEqual(loadedActions, expected) {
		t.Errorf("EffectiveActions after round-trip: expected %v, got %v", expected, loadedActions)
	}

	// Provision and verify actions in subject mapping calls.
	var mu sync.Mutex
	var requests []requestRecord

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, _ := io.ReadAll(r.Body)
		defer r.Body.Close()

		var bodyMap map[string]interface{}
		json.Unmarshal(bodyBytes, &bodyMap)

		mu.Lock()
		requests = append(requests, requestRecord{
			Method: r.Method,
			Path:   r.URL.Path,
			Body:   bodyMap,
		})
		mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		path := r.URL.Path
		switch {
		case strings.HasSuffix(path, "/CreateNamespace"):
			json.NewEncoder(w).Encode(map[string]interface{}{
				"namespace": map[string]interface{}{"id": "ns-1", "name": "tdflite.local"},
			})
		case strings.HasSuffix(path, "/CreateAttribute"):
			json.NewEncoder(w).Encode(map[string]interface{}{
				"attribute": map[string]interface{}{
					"id": "attr-1",
					"values": []interface{}{
						map[string]interface{}{"id": "val-1", "value": "eng"},
						map[string]interface{}{"id": "val-2", "value": "sales"},
					},
				},
			})
		case strings.HasSuffix(path, "/CreateSubjectMapping"):
			json.NewEncoder(w).Encode(map[string]interface{}{})
		default:
			http.Error(w, "not found", 404)
		}
	}))
	defer server.Close()

	ctx := context.Background()
	if err := provision.Provision(ctx, &loaded, server.URL, "test-token"); err != nil {
		t.Fatalf("Provision: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()

	// Verify subject mapping requests contain all 4 actions.
	for _, req := range requests {
		if !strings.HasSuffix(req.Path, "/CreateSubjectMapping") {
			continue
		}

		actionsRaw, ok := req.Body["actions"].([]interface{})
		if !ok {
			t.Fatal("subject mapping missing actions array")
		}

		if len(actionsRaw) != 4 {
			t.Errorf("expected 4 actions in subject mapping, got %d", len(actionsRaw))
		}

		actionNames := make([]string, 0, len(actionsRaw))
		for _, a := range actionsRaw {
			aMap, ok := a.(map[string]interface{})
			if !ok {
				t.Fatal("action is not a map")
			}
			name, _ := aMap["name"].(string)
			actionNames = append(actionNames, name)
		}

		if !reflect.DeepEqual(actionNames, expected) {
			t.Errorf("subject mapping actions: expected %v, got %v", expected, actionNames)
		}
	}
}

// ---------------------------------------------------------------------------
// Test 5: TestTokenTTLPropagation
// ---------------------------------------------------------------------------

func TestTokenTTLPropagation(t *testing.T) {
	bundle := &policybundle.Bundle{
		Attributes: []policybundle.Attribute{
			{Name: "level", Rule: policybundle.RuleHierarchy, Values: []string{"high", "low"}},
		},
		Identities: map[string]policybundle.Identity{
			"user1": {Claims: map[string]interface{}{"level": "high"}},
		},
		Options: &policybundle.Options{
			TokenTTL: "30m",
		},
	}

	pubPath, privPath := generateSSHKeyPair(t)

	if err := policybundle.SealWithSSHKey(bundle, pubPath); err != nil {
		t.Fatalf("SealWithSSHKey: %v", err)
	}
	if err := policybundle.SignBundle(bundle, privPath); err != nil {
		t.Fatalf("SignBundle: %v", err)
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

	// Verify Options survived.
	if loaded.Options == nil {
		t.Fatal("Options is nil after round-trip")
	}
	if loaded.Options.TokenTTL != "30m" {
		t.Errorf("TokenTTL after round-trip: expected %q, got %q", "30m", loaded.Options.TokenTTL)
	}
}

// ---------------------------------------------------------------------------
// Test 6: TestVersionPropagation
// ---------------------------------------------------------------------------

func TestVersionPropagation(t *testing.T) {
	bundle := &policybundle.Bundle{
		Version: 1,
		Attributes: []policybundle.Attribute{
			{Name: "level", Rule: policybundle.RuleHierarchy, Values: []string{"high", "low"}},
		},
		Identities: map[string]policybundle.Identity{
			"user1": {Claims: map[string]interface{}{"level": "high"}},
		},
	}

	pubPath, privPath := generateSSHKeyPair(t)

	if err := policybundle.SealWithSSHKey(bundle, pubPath); err != nil {
		t.Fatalf("SealWithSSHKey: %v", err)
	}
	if err := policybundle.SignBundle(bundle, privPath); err != nil {
		t.Fatalf("SignBundle: %v", err)
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

	if loaded.Version != 1 {
		t.Errorf("Version after round-trip: expected 1, got %d", loaded.Version)
	}
	if loaded.EffectiveVersion() != 1 {
		t.Errorf("EffectiveVersion after round-trip: expected 1, got %d", loaded.EffectiveVersion())
	}
}

// ---------------------------------------------------------------------------
// Test 7: TestSealedMethodField
// ---------------------------------------------------------------------------

func TestSealedMethodField(t *testing.T) {
	makeBundle := func() *policybundle.Bundle {
		return &policybundle.Bundle{
			Attributes: []policybundle.Attribute{
				{Name: "level", Rule: policybundle.RuleHierarchy, Values: []string{"high", "low"}},
			},
			Identities: map[string]policybundle.Identity{
				"user1": {Claims: map[string]interface{}{"level": "high"}},
			},
		}
	}

	t.Run("SSH key mode", func(t *testing.T) {
		bundle := makeBundle()
		pubPath, privPath := generateSSHKeyPair(t)

		if err := policybundle.SealWithSSHKey(bundle, pubPath); err != nil {
			t.Fatalf("SealWithSSHKey: %v", err)
		}
		if err := policybundle.SignBundle(bundle, privPath); err != nil {
			t.Fatalf("SignBundle: %v", err)
		}

		// Method should be "" (defaults to ssh).
		if bundle.Sealed.Method != "" {
			t.Errorf("SSH seal Method: expected empty string, got %q", bundle.Sealed.Method)
		}

		// Fingerprint should be non-empty.
		if bundle.Sealed.Fingerprint == "" {
			t.Error("SSH seal Fingerprint should be non-empty")
		}

		// Round-trip through JSON.
		data, err := json.Marshal(bundle)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		var loaded policybundle.Bundle
		if err := json.Unmarshal(data, &loaded); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}

		if loaded.Sealed.Method != "" {
			t.Errorf("SSH seal Method after round-trip: expected empty string, got %q", loaded.Sealed.Method)
		}
		if loaded.Sealed.Fingerprint == "" {
			t.Error("SSH seal Fingerprint should be non-empty after round-trip")
		}
	})

	t.Run("Passphrase mode", func(t *testing.T) {
		bundle := makeBundle()

		if err := policybundle.SealWithPassphrase(bundle, "test-passphrase"); err != nil {
			t.Fatalf("SealWithPassphrase: %v", err)
		}
		if err := policybundle.SignBundlePassphrase(bundle); err != nil {
			t.Fatalf("SignBundlePassphrase: %v", err)
		}

		// Method should be "passphrase".
		if bundle.Sealed.Method != "passphrase" {
			t.Errorf("Passphrase seal Method: expected %q, got %q", "passphrase", bundle.Sealed.Method)
		}

		// Fingerprint should be empty.
		if bundle.Sealed.Fingerprint != "" {
			t.Errorf("Passphrase seal Fingerprint should be empty, got %q", bundle.Sealed.Fingerprint)
		}

		// Round-trip through JSON.
		data, err := json.Marshal(bundle)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		var loaded policybundle.Bundle
		if err := json.Unmarshal(data, &loaded); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}

		if loaded.Sealed.Method != "passphrase" {
			t.Errorf("Passphrase seal Method after round-trip: expected %q, got %q", "passphrase", loaded.Sealed.Method)
		}
		if loaded.Sealed.Fingerprint != "" {
			t.Errorf("Passphrase seal Fingerprint should be empty after round-trip, got %q", loaded.Sealed.Fingerprint)
		}
	})
}

// ---------------------------------------------------------------------------
// Test 8: TestAllOptionalFieldsTogether
// ---------------------------------------------------------------------------

func TestAllOptionalFieldsTogether(t *testing.T) {
	bundle := &policybundle.Bundle{
		Version:   1,
		Namespace: "maxtest.example.com",
		Attributes: []policybundle.Attribute{
			{Name: "clearance", Rule: policybundle.RuleHierarchy, Values: []string{"top", "mid", "low"}},
			{Name: "programs", Rule: policybundle.RuleAllOf, Values: []string{"alpha", "beta", "gamma"}},
			{Name: "regions", Rule: policybundle.RuleAnyOf, Values: []string{"us", "eu", "apac"}},
		},
		Identities: map[string]policybundle.Identity{
			"admin-user": {
				Claims:       map[string]interface{}{"clearance": "top", "programs": []string{"alpha", "beta", "gamma"}, "regions": []string{"us", "eu", "apac"}},
				Admin:        true,
				Password:     "admin-pw-custom",
				ClientID:     "admin-custom-client",
				ClientSecret: "admin-custom-secret",
			},
			"power-user": {
				Claims:   map[string]interface{}{"clearance": "mid", "programs": []string{"alpha", "beta"}},
				Admin:    false,
				Password: "power-pw-custom",
			},
			"basic-user": {
				Claims: map[string]interface{}{"clearance": "low"},
			},
			"service-acct": {
				Claims:       map[string]interface{}{"clearance": "top", "programs": []string{"alpha", "beta", "gamma"}, "regions": []string{"us", "eu", "apac"}},
				ClientID:     "svc-custom-client",
				ClientSecret: "svc-custom-secret",
			},
			"minimal-user": {
				Claims: map[string]interface{}{"clearance": "low"},
			},
		},
		Options: &policybundle.Options{
			TokenTTL:       "1h",
			DefaultActions: []string{"read", "create", "update"},
		},
	}

	// Step 1: Validate.
	if err := bundle.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	// Step 2: Seal with SSH key.
	pubPath, privPath := generateSSHKeyPair(t)
	if err := policybundle.SealWithSSHKey(bundle, pubPath); err != nil {
		t.Fatalf("SealWithSSHKey: %v", err)
	}

	// Step 3: Sign.
	if err := policybundle.SignBundle(bundle, privPath); err != nil {
		t.Fatalf("SignBundle: %v", err)
	}

	if !bundle.IsSealed() {
		t.Fatal("expected IsSealed() == true")
	}

	// Step 4: Marshal to JSON.
	sealedJSON, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	// Step 5: Unmarshal back.
	var loaded policybundle.Bundle
	if err := json.Unmarshal(sealedJSON, &loaded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// Step 6: Verify signature.
	if err := policybundle.VerifySignature(&loaded, pubPath); err != nil {
		t.Fatalf("VerifySignature: %v", err)
	}

	// Step 7: Unseal.
	keys, err := policybundle.UnsealWithSSHKey(&loaded, privPath)
	if err != nil {
		t.Fatalf("UnsealWithSSHKey: %v", err)
	}

	// Step 8: Verify all keys work.
	testData := []byte("all optional fields test")
	digest := sha256.Sum256(testData)

	rsaSig, err := rsa.SignPKCS1v15(rand.Reader, keys.RSAPrivate, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("RSA sign: %v", err)
	}
	if err := rsa.VerifyPKCS1v15(&keys.RSAPrivate.PublicKey, crypto.SHA256, digest[:], rsaSig); err != nil {
		t.Fatalf("RSA verify: %v", err)
	}

	ecSig, err := ecdsa.SignASN1(rand.Reader, keys.ECPrivate, digest[:])
	if err != nil {
		t.Fatalf("EC sign: %v", err)
	}
	if !ecdsa.VerifyASN1(&keys.ECPrivate.PublicKey, digest[:], ecSig) {
		t.Fatal("EC verify failed")
	}

	if keys.IDPKey == nil {
		t.Fatal("IDPKey is nil")
	}
	if err := keys.IDPKey.Validate(); err != nil {
		t.Fatalf("IDPKey validation: %v", err)
	}

	// Verify all top-level optional fields survived.
	if loaded.Version != 1 {
		t.Errorf("Version: expected 1, got %d", loaded.Version)
	}
	if loaded.EffectiveVersion() != 1 {
		t.Errorf("EffectiveVersion: expected 1, got %d", loaded.EffectiveVersion())
	}
	if loaded.Namespace != "maxtest.example.com" {
		t.Errorf("Namespace: expected %q, got %q", "maxtest.example.com", loaded.Namespace)
	}
	if loaded.EffectiveNamespace() != "maxtest.example.com" {
		t.Errorf("EffectiveNamespace: expected %q, got %q", "maxtest.example.com", loaded.EffectiveNamespace())
	}
	if loaded.Options == nil {
		t.Fatal("Options is nil after round-trip")
	}
	if loaded.Options.TokenTTL != "1h" {
		t.Errorf("TokenTTL: expected %q, got %q", "1h", loaded.Options.TokenTTL)
	}
	expectedActions := []string{"read", "create", "update"}
	if !reflect.DeepEqual(loaded.EffectiveActions(), expectedActions) {
		t.Errorf("EffectiveActions: expected %v, got %v", expectedActions, loaded.EffectiveActions())
	}

	// Step 9: GenerateIdentities.
	output, err := policybundle.GenerateIdentities(&loaded)
	if err != nil {
		t.Fatalf("GenerateIdentities: %v", err)
	}

	// 5 users + 2 built-in clients.
	if len(output.Users) != 5 {
		t.Fatalf("expected 5 users, got %d", len(output.Users))
	}
	if len(output.Clients) != 2 {
		t.Fatalf("expected 2 clients, got %d", len(output.Clients))
	}

	usersByName := make(map[string]struct {
		ClientID     string
		ClientSecret string
		Password     string
		Roles        []string
		Claims       map[string]any
	})
	for _, u := range output.Users {
		usersByName[u.Username] = struct {
			ClientID     string
			ClientSecret string
			Password     string
			Roles        []string
			Claims       map[string]any
		}{u.ClientID, u.ClientSecret, u.Password, u.Roles, u.CustomClaims}
	}

	// Step 10: Verify every optional field on every identity.

	// admin-user: admin, custom password, custom client_id, custom client_secret.
	adminUser := usersByName["admin-user"]
	if adminUser.Password != "admin-pw-custom" {
		t.Errorf("admin-user password: expected %q, got %q", "admin-pw-custom", adminUser.Password)
	}
	if adminUser.ClientID != "admin-custom-client" {
		t.Errorf("admin-user client_id: expected %q, got %q", "admin-custom-client", adminUser.ClientID)
	}
	if adminUser.ClientSecret != "admin-custom-secret" {
		t.Errorf("admin-user client_secret: expected %q, got %q", "admin-custom-secret", adminUser.ClientSecret)
	}
	adminRoles := make([]string, len(adminUser.Roles))
	copy(adminRoles, adminUser.Roles)
	sort.Strings(adminRoles)
	if !reflect.DeepEqual(adminRoles, []string{"opentdf-admin", "opentdf-standard"}) {
		t.Errorf("admin-user roles: expected [opentdf-admin opentdf-standard], got %v", adminRoles)
	}
	if adminUser.Claims == nil {
		t.Error("admin-user has nil custom claims")
	} else {
		if adminUser.Claims["clearance"] != "top" {
			t.Errorf("admin-user clearance claim: expected %q, got %v", "top", adminUser.Claims["clearance"])
		}
	}

	// power-user: not admin, custom password, default client_id/secret.
	powerUser := usersByName["power-user"]
	if powerUser.Password != "power-pw-custom" {
		t.Errorf("power-user password: expected %q, got %q", "power-pw-custom", powerUser.Password)
	}
	if powerUser.ClientID != "power-user-client" {
		t.Errorf("power-user client_id: expected %q, got %q", "power-user-client", powerUser.ClientID)
	}
	if powerUser.ClientSecret != "power-user-secret" {
		t.Errorf("power-user client_secret: expected %q, got %q", "power-user-secret", powerUser.ClientSecret)
	}
	if !reflect.DeepEqual(powerUser.Roles, []string{"opentdf-standard"}) {
		t.Errorf("power-user roles: expected [opentdf-standard], got %v", powerUser.Roles)
	}

	// basic-user: all defaults.
	basicUser := usersByName["basic-user"]
	if basicUser.Password != "basic-user-secret" {
		t.Errorf("basic-user password: expected %q, got %q", "basic-user-secret", basicUser.Password)
	}
	if basicUser.ClientID != "basic-user-client" {
		t.Errorf("basic-user client_id: expected %q, got %q", "basic-user-client", basicUser.ClientID)
	}
	if basicUser.ClientSecret != "basic-user-secret" {
		t.Errorf("basic-user client_secret: expected %q, got %q", "basic-user-secret", basicUser.ClientSecret)
	}
	if !reflect.DeepEqual(basicUser.Roles, []string{"opentdf-standard"}) {
		t.Errorf("basic-user roles: expected [opentdf-standard], got %v", basicUser.Roles)
	}

	// service-acct: custom client_id + client_secret, default password.
	svcAcct := usersByName["service-acct"]
	if svcAcct.Password != "service-acct-secret" {
		t.Errorf("service-acct password: expected %q, got %q", "service-acct-secret", svcAcct.Password)
	}
	if svcAcct.ClientID != "svc-custom-client" {
		t.Errorf("service-acct client_id: expected %q, got %q", "svc-custom-client", svcAcct.ClientID)
	}
	if svcAcct.ClientSecret != "svc-custom-secret" {
		t.Errorf("service-acct client_secret: expected %q, got %q", "svc-custom-secret", svcAcct.ClientSecret)
	}

	// minimal-user: all defaults, 1 claim.
	minUser := usersByName["minimal-user"]
	if minUser.Password != "minimal-user-secret" {
		t.Errorf("minimal-user password: expected %q, got %q", "minimal-user-secret", minUser.Password)
	}
	if minUser.ClientID != "minimal-user-client" {
		t.Errorf("minimal-user client_id: expected %q, got %q", "minimal-user-client", minUser.ClientID)
	}
	if len(minUser.Claims) != 1 {
		t.Errorf("minimal-user should have 1 claim, got %d: %v", len(minUser.Claims), minUser.Claims)
	}

	// Step 11: Provision against mock and verify namespace, actions, selectors.
	var mu sync.Mutex
	var requests []requestRecord

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, _ := io.ReadAll(r.Body)
		defer r.Body.Close()

		var bodyMap map[string]interface{}
		json.Unmarshal(bodyBytes, &bodyMap)

		mu.Lock()
		requests = append(requests, requestRecord{
			Method: r.Method,
			Path:   r.URL.Path,
			Body:   bodyMap,
		})
		mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		path := r.URL.Path
		switch {
		case strings.HasSuffix(path, "/CreateNamespace"):
			json.NewEncoder(w).Encode(map[string]interface{}{
				"namespace": map[string]interface{}{"id": "ns-max", "name": "maxtest.example.com"},
			})
		case strings.HasSuffix(path, "/CreateAttribute"):
			attrName, _ := bodyMap["name"].(string)
			var resp map[string]interface{}
			switch attrName {
			case "clearance":
				resp = map[string]interface{}{
					"attribute": map[string]interface{}{
						"id": "attr-cl-1",
						"values": []interface{}{
							map[string]interface{}{"id": "val-cl-top", "value": "top"},
							map[string]interface{}{"id": "val-cl-mid", "value": "mid"},
							map[string]interface{}{"id": "val-cl-low", "value": "low"},
						},
					},
				}
			case "programs":
				resp = map[string]interface{}{
					"attribute": map[string]interface{}{
						"id": "attr-prog-1",
						"values": []interface{}{
							map[string]interface{}{"id": "val-prog-alpha", "value": "alpha"},
							map[string]interface{}{"id": "val-prog-beta", "value": "beta"},
							map[string]interface{}{"id": "val-prog-gamma", "value": "gamma"},
						},
					},
				}
			case "regions":
				resp = map[string]interface{}{
					"attribute": map[string]interface{}{
						"id": "attr-reg-1",
						"values": []interface{}{
							map[string]interface{}{"id": "val-reg-us", "value": "us"},
							map[string]interface{}{"id": "val-reg-eu", "value": "eu"},
							map[string]interface{}{"id": "val-reg-apac", "value": "apac"},
						},
					},
				}
			default:
				http.Error(w, fmt.Sprintf("unknown attr: %s", attrName), 400)
				return
			}
			json.NewEncoder(w).Encode(resp)
		case strings.HasSuffix(path, "/CreateSubjectMapping"):
			json.NewEncoder(w).Encode(map[string]interface{}{})
		default:
			http.Error(w, "not found", 404)
		}
	}))
	defer server.Close()

	ctx := context.Background()
	if err := provision.Provision(ctx, &loaded, server.URL, "test-token"); err != nil {
		t.Fatalf("Provision: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()

	// Verify namespace call used "maxtest.example.com".
	for _, req := range requests {
		if strings.HasSuffix(req.Path, "/CreateNamespace") {
			nsName, _ := req.Body["name"].(string)
			if nsName != "maxtest.example.com" {
				t.Errorf("CreateNamespace used %q, expected %q", nsName, "maxtest.example.com")
			}
		}
	}

	// Verify all subject mapping calls have 3 actions.
	for _, req := range requests {
		if !strings.HasSuffix(req.Path, "/CreateSubjectMapping") {
			continue
		}

		actionsRaw, ok := req.Body["actions"].([]interface{})
		if !ok {
			t.Fatal("subject mapping missing actions array")
		}
		if len(actionsRaw) != 3 {
			t.Errorf("expected 3 actions, got %d", len(actionsRaw))
		}

		// Verify correct selectors.
		newSCS, ok := req.Body["newSubjectConditionSet"].(map[string]interface{})
		if !ok {
			continue
		}
		subjectSets, ok := newSCS["subjectSets"].([]interface{})
		if !ok || len(subjectSets) == 0 {
			continue
		}
		ss := subjectSets[0].(map[string]interface{})
		condGroups := ss["conditionGroups"].([]interface{})
		cg := condGroups[0].(map[string]interface{})
		conditions := cg["conditions"].([]interface{})
		cond := conditions[0].(map[string]interface{})
		selector := cond["subjectExternalSelectorValue"].(string)
		valueID, _ := req.Body["attributeValueId"].(string)

		switch {
		case strings.HasPrefix(valueID, "val-cl-"):
			// clearance is hierarchy -> ".clearance"
			if selector != ".clearance" {
				t.Errorf("clearance selector: expected %q, got %q", ".clearance", selector)
			}
		case strings.HasPrefix(valueID, "val-prog-"):
			// programs is allOf -> ".programs[]"
			if selector != ".programs[]" {
				t.Errorf("programs selector: expected %q, got %q", ".programs[]", selector)
			}
		case strings.HasPrefix(valueID, "val-reg-"):
			// regions is anyOf -> ".regions[]"
			if selector != ".regions[]" {
				t.Errorf("regions selector: expected %q, got %q", ".regions[]", selector)
			}
		}
	}

	// Verify total subject mappings: 3 (clearance) + 3 (programs) + 3 (regions) = 9.
	smCount := 0
	for _, req := range requests {
		if strings.HasSuffix(req.Path, "/CreateSubjectMapping") {
			smCount++
		}
	}
	if smCount != 9 {
		t.Errorf("expected 9 subject mappings, got %d", smCount)
	}
}

// ---------------------------------------------------------------------------
// Test 9: TestEmptyOptionsVsNilOptions
// ---------------------------------------------------------------------------

func TestEmptyOptionsVsNilOptions(t *testing.T) {
	makeBundle := func(opts *policybundle.Options) *policybundle.Bundle {
		return &policybundle.Bundle{
			Attributes: []policybundle.Attribute{
				{Name: "level", Rule: policybundle.RuleHierarchy, Values: []string{"high", "low"}},
			},
			Identities: map[string]policybundle.Identity{
				"user1": {Claims: map[string]interface{}{"level": "high"}},
			},
			Options: opts,
		}
	}

	defaultActions := policybundle.DefaultActions

	t.Run("nil options", func(t *testing.T) {
		b := makeBundle(nil)
		got := b.EffectiveActions()
		if !reflect.DeepEqual(got, defaultActions) {
			t.Errorf("nil Options: expected %v, got %v", defaultActions, got)
		}
	})

	t.Run("empty options struct", func(t *testing.T) {
		b := makeBundle(&policybundle.Options{})
		got := b.EffectiveActions()
		if !reflect.DeepEqual(got, defaultActions) {
			t.Errorf("empty Options: expected %v, got %v", defaultActions, got)
		}
	})

	t.Run("empty default_actions slice", func(t *testing.T) {
		b := makeBundle(&policybundle.Options{DefaultActions: []string{}})
		got := b.EffectiveActions()
		if !reflect.DeepEqual(got, defaultActions) {
			t.Errorf("empty DefaultActions: expected %v, got %v", defaultActions, got)
		}
	})

	t.Run("explicit single action", func(t *testing.T) {
		b := makeBundle(&policybundle.Options{DefaultActions: []string{"read"}})
		got := b.EffectiveActions()
		expected := []string{"read"}
		if !reflect.DeepEqual(got, expected) {
			t.Errorf("explicit single action: expected %v, got %v", expected, got)
		}
	})

	// Also verify round-trip behavior for each case.
	t.Run("nil options round-trip", func(t *testing.T) {
		b := makeBundle(nil)
		data, err := json.Marshal(b)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		var loaded policybundle.Bundle
		if err := json.Unmarshal(data, &loaded); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if loaded.Options != nil {
			t.Error("nil Options should remain nil after round-trip")
		}
		got := loaded.EffectiveActions()
		if !reflect.DeepEqual(got, defaultActions) {
			t.Errorf("nil Options after round-trip: expected %v, got %v", defaultActions, got)
		}
	})

	t.Run("explicit actions round-trip", func(t *testing.T) {
		b := makeBundle(&policybundle.Options{DefaultActions: []string{"read"}})
		data, err := json.Marshal(b)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		var loaded policybundle.Bundle
		if err := json.Unmarshal(data, &loaded); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if loaded.Options == nil {
			t.Fatal("Options should not be nil after round-trip")
		}
		got := loaded.EffectiveActions()
		expected := []string{"read"}
		if !reflect.DeepEqual(got, expected) {
			t.Errorf("explicit actions after round-trip: expected %v, got %v", expected, got)
		}
	})
}
