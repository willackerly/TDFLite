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
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/willackerly/TDFLite/internal/policybundle"
	"github.com/willackerly/TDFLite/internal/provision"
	"golang.org/x/crypto/ssh"
)

// ---------------------------------------------------------------------------
// Mock ConnectRPC server infrastructure
// ---------------------------------------------------------------------------

// recordedCall stores a single API call to the mock server.
type recordedCall struct {
	ServiceMethod string // e.g. "CreateNamespace", "CreateAttribute", "CreateSubjectMapping"
	Path          string
	Body          map[string]interface{}
}

// mockConnectServer records all provisioning calls and returns appropriate responses.
type mockConnectServer struct {
	mu    sync.Mutex
	calls []recordedCall

	// attrCounter generates unique IDs for attributes and values.
	attrCounter int
	valCounter  int
}

func newMockConnectServer() *mockConnectServer {
	return &mockConnectServer{}
}

// reset clears all recorded calls (used between phases).
func (m *mockConnectServer) reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = nil
	m.attrCounter = 0
	m.valCounter = 0
}

// getCalls returns a copy of all recorded calls.
func (m *mockConnectServer) getCalls() []recordedCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]recordedCall, len(m.calls))
	copy(result, m.calls)
	return result
}

// handler returns an http.Handler that records calls and returns mock responses.
func (m *mockConnectServer) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read error", 500)
			return
		}
		defer r.Body.Close()

		var bodyMap map[string]interface{}
		if err := json.Unmarshal(bodyBytes, &bodyMap); err != nil {
			bodyMap = nil
		}

		path := r.URL.Path

		// Determine the service method from the path.
		var serviceMethod string
		switch {
		case strings.HasSuffix(path, "/CreateNamespace"):
			serviceMethod = "CreateNamespace"
		case strings.HasSuffix(path, "/ListNamespaces"):
			serviceMethod = "ListNamespaces"
		case strings.HasSuffix(path, "/CreateAttribute"):
			serviceMethod = "CreateAttribute"
		case strings.HasSuffix(path, "/CreateSubjectMapping"):
			serviceMethod = "CreateSubjectMapping"
		default:
			serviceMethod = path
		}

		m.mu.Lock()
		m.calls = append(m.calls, recordedCall{
			ServiceMethod: serviceMethod,
			Path:          path,
			Body:          bodyMap,
		})
		m.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")

		switch serviceMethod {
		case "CreateNamespace":
			nsName, _ := bodyMap["name"].(string)
			resp := map[string]interface{}{
				"namespace": map[string]interface{}{
					"id":   "ns-0001",
					"name": nsName,
				},
			}
			json.NewEncoder(w).Encode(resp)

		case "CreateAttribute":
			attrName, _ := bodyMap["name"].(string)
			valuesRaw, _ := bodyMap["values"].([]interface{})

			m.mu.Lock()
			m.attrCounter++
			attrID := fmt.Sprintf("attr-%03d", m.attrCounter)

			values := make([]interface{}, len(valuesRaw))
			for i, v := range valuesRaw {
				m.valCounter++
				values[i] = map[string]interface{}{
					"id":    fmt.Sprintf("val-%03d", m.valCounter),
					"value": fmt.Sprintf("%v", v),
				}
			}
			m.mu.Unlock()

			resp := map[string]interface{}{
				"attribute": map[string]interface{}{
					"id":     attrID,
					"name":   attrName,
					"values": values,
				},
			}
			json.NewEncoder(w).Encode(resp)

		case "CreateSubjectMapping":
			json.NewEncoder(w).Encode(map[string]interface{}{})

		default:
			http.Error(w, "not found", 404)
		}
	})
}

// ---------------------------------------------------------------------------
// Verification helpers
// ---------------------------------------------------------------------------

// assertIdentityExists checks that a user with the given name exists in the output.
func assertIdentityExists(t *testing.T, output *policybundle.IdentityOutput, name string) {
	t.Helper()
	for _, u := range output.Users {
		if u.Username == name {
			return
		}
	}
	t.Errorf("expected identity %q to exist, but it was not found", name)
}

// assertIdentityNotExists checks that a user is NOT in the output.
func assertIdentityNotExists(t *testing.T, output *policybundle.IdentityOutput, name string) {
	t.Helper()
	for _, u := range output.Users {
		if u.Username == name {
			t.Errorf("expected identity %q to NOT exist, but it was found", name)
			return
		}
	}
}

// assertIdentityHasClaim checks that a user has a specific claim with expected value.
func assertIdentityHasClaim(t *testing.T, output *policybundle.IdentityOutput, name string, claimKey string, expectedValue interface{}) {
	t.Helper()
	for _, u := range output.Users {
		if u.Username != name {
			continue
		}
		if u.CustomClaims == nil {
			t.Errorf("identity %q has no custom claims, expected claim %q=%v", name, claimKey, expectedValue)
			return
		}
		val, ok := u.CustomClaims[claimKey]
		if !ok {
			t.Errorf("identity %q missing claim %q", name, claimKey)
			return
		}
		// Compare with type flexibility: []string vs []interface{} after JSON.
		if !claimValuesEqual(val, expectedValue) {
			t.Errorf("identity %q claim %q: expected %v (%T), got %v (%T)", name, claimKey, expectedValue, expectedValue, val, val)
		}
		return
	}
	t.Errorf("identity %q not found when checking claim %q", name, claimKey)
}

// assertIdentityNoClaim checks that a user does NOT have a specific claim.
func assertIdentityNoClaim(t *testing.T, output *policybundle.IdentityOutput, name string, claimKey string) {
	t.Helper()
	for _, u := range output.Users {
		if u.Username != name {
			continue
		}
		if u.CustomClaims == nil {
			return // No claims at all, so no such claim.
		}
		if _, ok := u.CustomClaims[claimKey]; ok {
			t.Errorf("identity %q should NOT have claim %q, but it does", name, claimKey)
		}
		return
	}
	t.Errorf("identity %q not found when checking absence of claim %q", name, claimKey)
}

// assertIdentityHasRole checks that a user has the specified role.
func assertIdentityHasRole(t *testing.T, output *policybundle.IdentityOutput, name string, role string) {
	t.Helper()
	for _, u := range output.Users {
		if u.Username != name {
			continue
		}
		for _, r := range u.Roles {
			if r == role {
				return
			}
		}
		t.Errorf("identity %q expected to have role %q, but roles are %v", name, role, u.Roles)
		return
	}
	t.Errorf("identity %q not found when checking role %q", name, role)
}

// assertIdentityLacksRole checks that a user does NOT have the specified role.
func assertIdentityLacksRole(t *testing.T, output *policybundle.IdentityOutput, name string, role string) {
	t.Helper()
	for _, u := range output.Users {
		if u.Username != name {
			continue
		}
		for _, r := range u.Roles {
			if r == role {
				t.Errorf("identity %q should NOT have role %q, but it does", name, role)
				return
			}
		}
		return
	}
	t.Errorf("identity %q not found when checking lack of role %q", name, role)
}

// assertProvisionCallCount checks the number of API calls of a given type.
func assertProvisionCallCount(t *testing.T, calls []recordedCall, serviceMethod string, expected int) {
	t.Helper()
	count := 0
	for _, c := range calls {
		if c.ServiceMethod == serviceMethod {
			count++
		}
	}
	if count != expected {
		t.Errorf("expected %d %s calls, got %d", expected, serviceMethod, count)
	}
}

// assertProvisionUsedNamespace checks the namespace in CreateNamespace calls.
func assertProvisionUsedNamespace(t *testing.T, calls []recordedCall, expected string) {
	t.Helper()
	for _, c := range calls {
		if c.ServiceMethod != "CreateNamespace" {
			continue
		}
		name, _ := c.Body["name"].(string)
		if name != expected {
			t.Errorf("CreateNamespace: expected namespace %q, got %q", expected, name)
		}
		return
	}
	t.Error("no CreateNamespace call found")
}

// assertProvisionUsedActions checks that subject mapping calls used the expected actions.
func assertProvisionUsedActions(t *testing.T, calls []recordedCall, expected []string) {
	t.Helper()
	for _, c := range calls {
		if c.ServiceMethod != "CreateSubjectMapping" {
			continue
		}
		actions := extractActionsFromCall(c)
		sort.Strings(actions)
		sorted := make([]string, len(expected))
		copy(sorted, expected)
		sort.Strings(sorted)
		if !reflect.DeepEqual(actions, sorted) {
			t.Errorf("CreateSubjectMapping: expected actions %v, got %v", expected, actions)
			return
		}
	}
}

// extractActionsFromCall extracts action names from a CreateSubjectMapping call body.
func extractActionsFromCall(c recordedCall) []string {
	actionsRaw, ok := c.Body["actions"].([]interface{})
	if !ok {
		return nil
	}
	var result []string
	for _, a := range actionsRaw {
		aMap, ok := a.(map[string]interface{})
		if !ok {
			continue
		}
		name, _ := aMap["name"].(string)
		if name != "" {
			result = append(result, name)
		}
	}
	return result
}

// claimValuesEqual compares two claim values, handling []string vs []interface{} differences.
func claimValuesEqual(a, b interface{}) bool {
	// Try direct equality first.
	if reflect.DeepEqual(a, b) {
		return true
	}
	// Convert both to string representation and compare.
	aStr := normalizeClaimValue(a)
	bStr := normalizeClaimValue(b)
	return reflect.DeepEqual(aStr, bStr)
}

// normalizeClaimValue converts a claim value to a canonical form for comparison.
func normalizeClaimValue(v interface{}) interface{} {
	switch val := v.(type) {
	case []interface{}:
		result := make([]string, len(val))
		for i, item := range val {
			result[i] = fmt.Sprintf("%v", item)
		}
		return result
	case []string:
		return val
	default:
		return fmt.Sprintf("%v", v)
	}
}

// ---------------------------------------------------------------------------
// Bundle builder helpers
// ---------------------------------------------------------------------------

// makeBundle constructs a Bundle from the given definition programmatically.
func makeBundle(
	namespace string,
	attrs []policybundle.Attribute,
	identities map[string]policybundle.Identity,
	options *policybundle.Options,
) *policybundle.Bundle {
	return &policybundle.Bundle{
		Version:    1,
		Namespace:  namespace,
		Attributes: attrs,
		Identities: identities,
		Options:    options,
	}
}

// makeIdentity constructs a policybundle.Identity with the given claims and admin flag.
func makeIdentity(admin bool, claims map[string]interface{}) policybundle.Identity {
	return policybundle.Identity{
		Admin:  admin,
		Claims: claims,
	}
}

// lifecycleSealAndSign seals a bundle with SSH key and signs it.
func lifecycleSealAndSign(t *testing.T, bundle *policybundle.Bundle, pubPath, privPath string) {
	t.Helper()
	if err := policybundle.SealWithSSHKey(bundle, pubPath); err != nil {
		t.Fatalf("SealWithSSHKey: %v", err)
	}
	if err := policybundle.SignBundle(bundle, privPath); err != nil {
		t.Fatalf("SignBundle: %v", err)
	}
}

// provisionAndCollect runs provisioning against the mock server and returns calls.
func provisionAndCollect(t *testing.T, bundle *policybundle.Bundle, mock *mockConnectServer, serverURL string) []recordedCall {
	t.Helper()
	mock.reset()
	ctx := context.Background()
	err := provision.Provision(ctx, bundle, serverURL, "test-token")
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	return mock.getCalls()
}

// generateIdentitiesOrFail calls GenerateIdentities and fails the test on error.
func generateIdentitiesOrFail(t *testing.T, bundle *policybundle.Bundle) *policybundle.IdentityOutput {
	t.Helper()
	output, err := policybundle.GenerateIdentities(bundle)
	if err != nil {
		t.Fatalf("GenerateIdentities: %v", err)
	}
	return output
}

// generateSSHKeyPairInDir creates an Ed25519 SSH key pair in the given directory.
// Returns (pubPath, privPath).
func generateSSHKeyPairInDir(t *testing.T, dir string) (string, string) {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating ed25519 key: %v", err)
	}

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
// TestPolicyLifecycle — the main lifecycle integration test
// ---------------------------------------------------------------------------

func TestPolicyLifecycle(t *testing.T) {
	// Use low work factor for fast tests.
	policybundle.SetSealWorkFactor(10)

	// Generate SSH keypair used across phases 1-5.
	keyDir := t.TempDir()
	pubPath, privPath := generateSSHKeyPairInDir(t, keyDir)

	// Start mock ConnectRPC server.
	mock := newMockConnectServer()
	server := httptest.NewServer(mock.handler())
	defer server.Close()

	// -----------------------------------------------------------------------
	// Phase 1: Initial deployment
	// -----------------------------------------------------------------------
	t.Run("Phase1_InitialDeployment", func(t *testing.T) {
		bundle := makeBundle("", // default namespace
			[]policybundle.Attribute{
				{Name: "classification", Rule: policybundle.RuleHierarchy, Values: []string{"TOP_SECRET", "SECRET", "CONFIDENTIAL", "UNCLASSIFIED"}},
				{Name: "compartment", Rule: policybundle.RuleAllOf, Values: []string{"SI", "TK", "HCS"}},
				{Name: "releasability", Rule: policybundle.RuleAllOf, Values: []string{"USA", "GBR", "CAN", "AUS", "NZL"}},
			},
			map[string]policybundle.Identity{
				"alice": makeIdentity(true, map[string]interface{}{
					"classification": "TOP_SECRET",
					"compartment":    []string{"SI", "TK", "HCS"},
					"releasability":  []string{"USA", "GBR", "CAN", "AUS", "NZL"},
				}),
				"bob": makeIdentity(false, map[string]interface{}{
					"classification": "SECRET",
					"releasability":  []string{"USA"},
				}),
				"carol": makeIdentity(false, map[string]interface{}{
					"classification": "CONFIDENTIAL",
					"releasability":  []string{"USA", "GBR"},
				}),
			},
			nil,
		)

		// Validate the bundle.
		if err := bundle.Validate(); err != nil {
			t.Fatalf("bundle validation: %v", err)
		}

		// Seal and sign.
		lifecycleSealAndSign(t, bundle, pubPath, privPath)

		// Verify sealed state.
		if !bundle.IsSealed() {
			t.Fatal("bundle should be sealed")
		}

		// Provision and verify call counts.
		calls := provisionAndCollect(t, bundle, mock, server.URL)
		assertProvisionCallCount(t, calls, "CreateNamespace", 1)
		assertProvisionCallCount(t, calls, "CreateAttribute", 3)
		// 4 + 3 + 5 = 12 subject mappings
		assertProvisionCallCount(t, calls, "CreateSubjectMapping", 12)

		// Generate identities and verify.
		output := generateIdentitiesOrFail(t, bundle)

		// 3 users + 2 built-in clients
		if len(output.Users) != 3 {
			t.Fatalf("expected 3 users, got %d", len(output.Users))
		}
		if len(output.Clients) != 2 {
			t.Fatalf("expected 2 clients, got %d", len(output.Clients))
		}

		// alice exists with admin role
		assertIdentityExists(t, output, "alice")
		assertIdentityHasRole(t, output, "alice", "opentdf-admin")
		assertIdentityHasRole(t, output, "alice", "opentdf-standard")

		// bob and carol exist without admin
		assertIdentityExists(t, output, "bob")
		assertIdentityLacksRole(t, output, "bob", "opentdf-admin")
		assertIdentityExists(t, output, "carol")
		assertIdentityLacksRole(t, output, "carol", "opentdf-admin")

		// alice has all compartments
		assertIdentityHasClaim(t, output, "alice", "compartment", []string{"SI", "TK", "HCS"})
		// bob has NO compartment claim
		assertIdentityNoClaim(t, output, "bob", "compartment")

		// Positive: alice has TOP_SECRET
		assertIdentityHasClaim(t, output, "alice", "classification", "TOP_SECRET")
		// bob has SECRET
		assertIdentityHasClaim(t, output, "bob", "classification", "SECRET")

		// Verify signature.
		if err := policybundle.VerifySignature(bundle, pubPath); err != nil {
			t.Fatalf("signature verification failed: %v", err)
		}

		// Unseal and verify keys are present.
		keys, err := policybundle.UnsealWithSSHKey(bundle, privPath)
		if err != nil {
			t.Fatalf("UnsealWithSSHKey: %v", err)
		}
		if keys.RSAPrivate == nil || keys.ECPrivate == nil || keys.IDPKey == nil {
			t.Fatal("expected all keys to be non-nil after unseal")
		}
	})

	// -----------------------------------------------------------------------
	// Phase 2: Promote bob
	// -----------------------------------------------------------------------
	t.Run("Phase2_PromoteBob", func(t *testing.T) {
		bundle := makeBundle("",
			[]policybundle.Attribute{
				{Name: "classification", Rule: policybundle.RuleHierarchy, Values: []string{"TOP_SECRET", "SECRET", "CONFIDENTIAL", "UNCLASSIFIED"}},
				{Name: "compartment", Rule: policybundle.RuleAllOf, Values: []string{"SI", "TK", "HCS"}},
				{Name: "releasability", Rule: policybundle.RuleAllOf, Values: []string{"USA", "GBR", "CAN", "AUS", "NZL"}},
			},
			map[string]policybundle.Identity{
				"alice": makeIdentity(true, map[string]interface{}{
					"classification": "TOP_SECRET",
					"compartment":    []string{"SI", "TK", "HCS"},
					"releasability":  []string{"USA", "GBR", "CAN", "AUS", "NZL"},
				}),
				"bob": makeIdentity(false, map[string]interface{}{
					"classification": "TOP_SECRET",         // promoted from SECRET
					"compartment":    []string{"SI"},        // added
					"releasability":  []string{"USA", "GBR"}, // expanded
				}),
				"carol": makeIdentity(false, map[string]interface{}{
					"classification": "CONFIDENTIAL",
					"releasability":  []string{"USA", "GBR"},
				}),
			},
			nil,
		)

		if err := bundle.Validate(); err != nil {
			t.Fatalf("bundle validation: %v", err)
		}

		lifecycleSealAndSign(t, bundle, pubPath, privPath)

		// Provision: same attributes, same counts.
		calls := provisionAndCollect(t, bundle, mock, server.URL)
		assertProvisionCallCount(t, calls, "CreateAttribute", 3)
		assertProvisionCallCount(t, calls, "CreateSubjectMapping", 12) // unchanged

		output := generateIdentitiesOrFail(t, bundle)

		// bob now has TOP_SECRET
		assertIdentityHasClaim(t, output, "bob", "classification", "TOP_SECRET")
		// bob now has compartment ["SI"]
		assertIdentityHasClaim(t, output, "bob", "compartment", []string{"SI"})
		// bob now has expanded releasability
		assertIdentityHasClaim(t, output, "bob", "releasability", []string{"USA", "GBR"})

		// alice is unchanged
		assertIdentityHasClaim(t, output, "alice", "classification", "TOP_SECRET")
		assertIdentityHasClaim(t, output, "alice", "compartment", []string{"SI", "TK", "HCS"})

		// carol is unchanged
		assertIdentityHasClaim(t, output, "carol", "classification", "CONFIDENTIAL")
		assertIdentityHasClaim(t, output, "carol", "releasability", []string{"USA", "GBR"})
	})

	// -----------------------------------------------------------------------
	// Phase 3: Add a new attribute and user
	// -----------------------------------------------------------------------
	t.Run("Phase3_AddAttributeAndUser", func(t *testing.T) {
		bundle := makeBundle("",
			[]policybundle.Attribute{
				{Name: "classification", Rule: policybundle.RuleHierarchy, Values: []string{"TOP_SECRET", "SECRET", "CONFIDENTIAL", "UNCLASSIFIED"}},
				{Name: "compartment", Rule: policybundle.RuleAllOf, Values: []string{"SI", "TK", "HCS"}},
				{Name: "releasability", Rule: policybundle.RuleAllOf, Values: []string{"USA", "GBR", "CAN", "AUS", "NZL"}},
				{Name: "program", Rule: policybundle.RuleAnyOf, Values: []string{"ALPHA", "BRAVO", "CHARLIE"}},
			},
			map[string]policybundle.Identity{
				"alice": makeIdentity(true, map[string]interface{}{
					"classification": "TOP_SECRET",
					"compartment":    []string{"SI", "TK", "HCS"},
					"releasability":  []string{"USA", "GBR", "CAN", "AUS", "NZL"},
					"program":        []string{"ALPHA", "BRAVO", "CHARLIE"},
				}),
				"bob": makeIdentity(false, map[string]interface{}{
					"classification": "TOP_SECRET",
					"compartment":    []string{"SI"},
					"releasability":  []string{"USA", "GBR"},
					"program":        []string{"ALPHA"},
				}),
				"carol": makeIdentity(false, map[string]interface{}{
					"classification": "CONFIDENTIAL",
					"releasability":  []string{"USA", "GBR"},
				}),
				"dave": makeIdentity(false, map[string]interface{}{
					"classification": "UNCLASSIFIED",
					"releasability":  []string{"USA"},
					"program":        []string{"BRAVO"},
				}),
			},
			nil,
		)

		if err := bundle.Validate(); err != nil {
			t.Fatalf("bundle validation: %v", err)
		}

		lifecycleSealAndSign(t, bundle, pubPath, privPath)

		// Provision: 4 attributes now, 12 + 3 = 15 subject mappings.
		calls := provisionAndCollect(t, bundle, mock, server.URL)
		assertProvisionCallCount(t, calls, "CreateAttribute", 4)
		assertProvisionCallCount(t, calls, "CreateSubjectMapping", 15)

		output := generateIdentitiesOrFail(t, bundle)

		// 4 user identities now.
		if len(output.Users) != 4 {
			t.Fatalf("expected 4 users, got %d", len(output.Users))
		}

		// dave exists with correct claims.
		assertIdentityExists(t, output, "dave")
		assertIdentityHasClaim(t, output, "dave", "classification", "UNCLASSIFIED")
		assertIdentityHasClaim(t, output, "dave", "releasability", []string{"USA"})
		assertIdentityHasClaim(t, output, "dave", "program", []string{"BRAVO"})

		// alice has all programs.
		assertIdentityHasClaim(t, output, "alice", "program", []string{"ALPHA", "BRAVO", "CHARLIE"})
		// bob has ALPHA only.
		assertIdentityHasClaim(t, output, "bob", "program", []string{"ALPHA"})

		// Verify new attribute uses anyOf selector format (.program[]).
		for _, c := range calls {
			if c.ServiceMethod != "CreateSubjectMapping" {
				continue
			}
			selector := extractSelector(c)
			if strings.Contains(selector, "program") {
				if selector != ".program[]" {
					t.Errorf("program selector should be '.program[]', got %q", selector)
				}
			}
		}
	})

	// -----------------------------------------------------------------------
	// Phase 4: Remove carol, restrict alice
	// -----------------------------------------------------------------------
	t.Run("Phase4_RemoveCarolRestrictAlice", func(t *testing.T) {
		bundle := makeBundle("",
			[]policybundle.Attribute{
				{Name: "classification", Rule: policybundle.RuleHierarchy, Values: []string{"TOP_SECRET", "SECRET", "CONFIDENTIAL", "UNCLASSIFIED"}},
				{Name: "compartment", Rule: policybundle.RuleAllOf, Values: []string{"SI", "TK", "HCS"}},
				{Name: "releasability", Rule: policybundle.RuleAllOf, Values: []string{"USA", "GBR", "CAN", "AUS", "NZL"}},
				{Name: "program", Rule: policybundle.RuleAnyOf, Values: []string{"ALPHA", "BRAVO", "CHARLIE"}},
			},
			map[string]policybundle.Identity{
				"alice": makeIdentity(true, map[string]interface{}{
					"classification": "TOP_SECRET",
					"compartment":    []string{"SI", "TK"}, // HCS removed
					"releasability":  []string{"USA", "GBR", "CAN", "AUS", "NZL"},
					"program":        []string{"ALPHA", "BRAVO"}, // CHARLIE removed
				}),
				"bob": makeIdentity(false, map[string]interface{}{
					"classification": "TOP_SECRET",
					"compartment":    []string{"SI"},
					"releasability":  []string{"USA", "GBR"},
					"program":        []string{"ALPHA"},
				}),
				// carol removed entirely
				"dave": makeIdentity(false, map[string]interface{}{
					"classification": "UNCLASSIFIED",
					"releasability":  []string{"USA"},
					"program":        []string{"BRAVO"},
				}),
			},
			nil,
		)

		if err := bundle.Validate(); err != nil {
			t.Fatalf("bundle validation: %v", err)
		}

		lifecycleSealAndSign(t, bundle, pubPath, privPath)

		output := generateIdentitiesOrFail(t, bundle)

		// 3 user identities now (carol gone).
		if len(output.Users) != 3 {
			t.Fatalf("expected 3 users, got %d", len(output.Users))
		}

		// carol is NOT in generated identities.
		assertIdentityNotExists(t, output, "carol")

		// alice's compartments are [SI, TK] (HCS removed).
		assertIdentityHasClaim(t, output, "alice", "compartment", []string{"SI", "TK"})
		// alice's programs are [ALPHA, BRAVO] (CHARLIE removed).
		assertIdentityHasClaim(t, output, "alice", "program", []string{"ALPHA", "BRAVO"})

		// Attributes unchanged: 4 attrs, still 15 subject mappings.
		calls := provisionAndCollect(t, bundle, mock, server.URL)
		assertProvisionCallCount(t, calls, "CreateAttribute", 4)
		assertProvisionCallCount(t, calls, "CreateSubjectMapping", 15)

		// bob and dave unchanged.
		assertIdentityHasClaim(t, output, "bob", "classification", "TOP_SECRET")
		assertIdentityHasClaim(t, output, "dave", "classification", "UNCLASSIFIED")
	})

	// -----------------------------------------------------------------------
	// Phase 5: Change namespace and options
	// -----------------------------------------------------------------------
	t.Run("Phase5_ChangeNamespaceAndOptions", func(t *testing.T) {
		bundle := makeBundle("defense.mil",
			[]policybundle.Attribute{
				{Name: "classification", Rule: policybundle.RuleHierarchy, Values: []string{"TOP_SECRET", "SECRET", "CONFIDENTIAL", "UNCLASSIFIED"}},
				{Name: "compartment", Rule: policybundle.RuleAllOf, Values: []string{"SI", "TK", "HCS"}},
				{Name: "releasability", Rule: policybundle.RuleAllOf, Values: []string{"USA", "GBR", "CAN", "AUS", "NZL"}},
				{Name: "program", Rule: policybundle.RuleAnyOf, Values: []string{"ALPHA", "BRAVO", "CHARLIE"}},
			},
			map[string]policybundle.Identity{
				"alice": makeIdentity(true, map[string]interface{}{
					"classification": "TOP_SECRET",
					"compartment":    []string{"SI", "TK"},
					"releasability":  []string{"USA", "GBR", "CAN", "AUS", "NZL"},
					"program":        []string{"ALPHA", "BRAVO"},
				}),
				"bob": makeIdentity(false, map[string]interface{}{
					"classification": "TOP_SECRET",
					"compartment":    []string{"SI"},
					"releasability":  []string{"USA", "GBR"},
					"program":        []string{"ALPHA"},
				}),
				"dave": makeIdentity(false, map[string]interface{}{
					"classification": "UNCLASSIFIED",
					"releasability":  []string{"USA"},
					"program":        []string{"BRAVO"},
				}),
			},
			&policybundle.Options{
				DefaultActions: []string{"read"},
				TokenTTL:       "2m",
			},
		)

		if err := bundle.Validate(); err != nil {
			t.Fatalf("bundle validation: %v", err)
		}

		lifecycleSealAndSign(t, bundle, pubPath, privPath)

		calls := provisionAndCollect(t, bundle, mock, server.URL)

		// Namespace in provisioning call is "defense.mil".
		assertProvisionUsedNamespace(t, calls, "defense.mil")

		// Subject mappings use only ["read"] action.
		assertProvisionUsedActions(t, calls, []string{"read"})

		// token_ttl is "2m" in options.
		if bundle.Options == nil || bundle.Options.TokenTTL != "2m" {
			t.Errorf("expected token_ttl '2m', got %v", bundle.Options)
		}

		// All identities and attributes otherwise unchanged.
		output := generateIdentitiesOrFail(t, bundle)
		if len(output.Users) != 3 {
			t.Fatalf("expected 3 users, got %d", len(output.Users))
		}
		assertIdentityExists(t, output, "alice")
		assertIdentityExists(t, output, "bob")
		assertIdentityExists(t, output, "dave")
		assertIdentityHasRole(t, output, "alice", "opentdf-admin")
	})

	// -----------------------------------------------------------------------
	// Phase 6: Key rotation (rebind)
	// -----------------------------------------------------------------------
	t.Run("Phase6_KeyRotation", func(t *testing.T) {
		// Create the bundle for this phase (same as end of phase 5).
		bundle := makeBundle("defense.mil",
			[]policybundle.Attribute{
				{Name: "classification", Rule: policybundle.RuleHierarchy, Values: []string{"TOP_SECRET", "SECRET", "CONFIDENTIAL", "UNCLASSIFIED"}},
				{Name: "compartment", Rule: policybundle.RuleAllOf, Values: []string{"SI", "TK", "HCS"}},
				{Name: "releasability", Rule: policybundle.RuleAllOf, Values: []string{"USA", "GBR", "CAN", "AUS", "NZL"}},
				{Name: "program", Rule: policybundle.RuleAnyOf, Values: []string{"ALPHA", "BRAVO", "CHARLIE"}},
			},
			map[string]policybundle.Identity{
				"alice": makeIdentity(true, map[string]interface{}{
					"classification": "TOP_SECRET",
					"compartment":    []string{"SI", "TK"},
					"releasability":  []string{"USA", "GBR", "CAN", "AUS", "NZL"},
					"program":        []string{"ALPHA", "BRAVO"},
				}),
				"bob": makeIdentity(false, map[string]interface{}{
					"classification": "TOP_SECRET",
					"compartment":    []string{"SI"},
					"releasability":  []string{"USA", "GBR"},
					"program":        []string{"ALPHA"},
				}),
				"dave": makeIdentity(false, map[string]interface{}{
					"classification": "UNCLASSIFIED",
					"releasability":  []string{"USA"},
					"program":        []string{"BRAVO"},
				}),
			},
			&policybundle.Options{
				DefaultActions: []string{"read"},
				TokenTTL:       "2m",
			},
		)

		// Seal and sign with old key.
		lifecycleSealAndSign(t, bundle, pubPath, privPath)

		// Verify unseal works with old key.
		oldKeys, err := policybundle.UnsealWithSSHKey(bundle, privPath)
		if err != nil {
			t.Fatalf("UnsealWithSSHKey (old key): %v", err)
		}
		if oldKeys.RSAPrivate == nil {
			t.Fatal("expected RSA key from unseal with old key")
		}

		// Generate a NEW SSH keypair.
		newKeyDir := t.TempDir()
		newPubPath, newPrivPath := generateSSHKeyPairInDir(t, newKeyDir)

		// RebindSSHKey from old key to new key.
		if err := policybundle.RebindSSHKey(bundle, privPath, newPrivPath); err != nil {
			t.Fatalf("RebindSSHKey: %v", err)
		}

		// Unseal with NEW key -> must succeed.
		newKeys, err := policybundle.UnsealWithSSHKey(bundle, newPrivPath)
		if err != nil {
			t.Fatalf("UnsealWithSSHKey (new key): %v", err)
		}
		if newKeys.RSAPrivate == nil || newKeys.ECPrivate == nil || newKeys.IDPKey == nil {
			t.Fatal("expected all keys after rebind unseal")
		}

		// Unseal with OLD key -> must FAIL.
		_, err = policybundle.UnsealWithSSHKey(bundle, privPath)
		if err == nil {
			t.Fatal("expected unseal with OLD key to FAIL after rebind, but it succeeded")
		}

		// Verify signature with new key's public key.
		if err := policybundle.VerifySignature(bundle, newPubPath); err != nil {
			t.Fatalf("signature verification with new key failed: %v", err)
		}

		// Verify signature with old key's public key should FAIL.
		if err := policybundle.VerifySignature(bundle, pubPath); err == nil {
			t.Fatal("expected signature verification with OLD public key to fail after rebind")
		}

		// Verify all policy content is unchanged after rebind.
		if len(bundle.Attributes) != 4 {
			t.Errorf("expected 4 attributes after rebind, got %d", len(bundle.Attributes))
		}
		if len(bundle.Identities) != 3 {
			t.Errorf("expected 3 identities after rebind, got %d", len(bundle.Identities))
		}
		if bundle.Namespace != "defense.mil" {
			t.Errorf("expected namespace 'defense.mil' after rebind, got %q", bundle.Namespace)
		}
		if bundle.Options == nil || bundle.Options.TokenTTL != "2m" {
			t.Error("expected options preserved after rebind")
		}

		// Verify the rebound keys still decrypt to working crypto material.
		if err := newKeys.RSAPrivate.Validate(); err != nil {
			t.Fatalf("RSA key validation after rebind: %v", err)
		}
		if err := newKeys.IDPKey.Validate(); err != nil {
			t.Fatalf("IDP key validation after rebind: %v", err)
		}

		// Verify identity generation still works on rebound bundle.
		output := generateIdentitiesOrFail(t, bundle)
		assertIdentityExists(t, output, "alice")
		assertIdentityExists(t, output, "bob")
		assertIdentityExists(t, output, "dave")
		assertIdentityHasRole(t, output, "alice", "opentdf-admin")
		assertIdentityHasClaim(t, output, "alice", "classification", "TOP_SECRET")
	})
}

// extractSelector extracts the subjectExternalSelectorValue from a CreateSubjectMapping call.
func extractSelector(c recordedCall) string {
	newSCS, ok := c.Body["newSubjectConditionSet"].(map[string]interface{})
	if !ok {
		return ""
	}
	subjectSets, ok := newSCS["subjectSets"].([]interface{})
	if !ok || len(subjectSets) == 0 {
		return ""
	}
	ss, ok := subjectSets[0].(map[string]interface{})
	if !ok {
		return ""
	}
	condGroups, ok := ss["conditionGroups"].([]interface{})
	if !ok || len(condGroups) == 0 {
		return ""
	}
	cg, ok := condGroups[0].(map[string]interface{})
	if !ok {
		return ""
	}
	conditions, ok := cg["conditions"].([]interface{})
	if !ok || len(conditions) == 0 {
		return ""
	}
	cond, ok := conditions[0].(map[string]interface{})
	if !ok {
		return ""
	}
	selector, _ := cond["subjectExternalSelectorValue"].(string)
	return selector
}
