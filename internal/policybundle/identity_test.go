package policybundle

import (
	"reflect"
	"testing"
)

// ---------------------------------------------------------------------------
// GenerateIdentities tests
// ---------------------------------------------------------------------------

// identityTestBundle creates a bundle with the given identities for testing.
func identityTestBundle(identities map[string]Identity) *Bundle {
	return &Bundle{
		Version:   1,
		Namespace: "test.local",
		Attributes: []Attribute{
			{Name: "clearance", Rule: RuleHierarchy, Values: []string{"top-secret", "secret", "unclassified"}},
			{Name: "groups", Rule: RuleAllOf, Values: []string{"eng", "ops", "finance"}},
		},
		Identities: identities,
	}
}

func TestGenerateIdentities(t *testing.T) {
	bundle := identityTestBundle(map[string]Identity{
		"alice": {
			Claims: map[string]interface{}{
				"clearance": "top-secret",
				"groups":    []string{"eng", "ops"},
			},
			Admin: true,
		},
		"bob": {
			Claims: map[string]interface{}{
				"clearance": "secret",
			},
		},
	})

	out, err := GenerateIdentities(bundle)
	if err != nil {
		t.Fatalf("GenerateIdentities error: %v", err)
	}

	// 2 user identities + 2 built-in clients = 4 total.
	all := out.All()
	if len(all) != 4 {
		t.Fatalf("expected 4 total identities, got %d", len(all))
	}
	if len(out.Users) != 2 {
		t.Fatalf("expected 2 users, got %d", len(out.Users))
	}
	if len(out.Clients) != 2 {
		t.Fatalf("expected 2 clients, got %d", len(out.Clients))
	}

	// Users are sorted by name: alice, bob.
	alice := out.Users[0]
	bob := out.Users[1]

	if alice.Username != "alice" {
		t.Errorf("expected first user to be alice, got %q", alice.Username)
	}
	if bob.Username != "bob" {
		t.Errorf("expected second user to be bob, got %q", bob.Username)
	}

	// Admin user has admin role.
	wantAdminRoles := []string{"opentdf-admin", "opentdf-standard"}
	if !reflect.DeepEqual(alice.Roles, wantAdminRoles) {
		t.Errorf("alice roles: got %v, want %v", alice.Roles, wantAdminRoles)
	}

	// Non-admin user has standard role only.
	wantStdRoles := []string{"opentdf-standard"}
	if !reflect.DeepEqual(bob.Roles, wantStdRoles) {
		t.Errorf("bob roles: got %v, want %v", bob.Roles, wantStdRoles)
	}

	// Credentials match Effective* methods.
	aliceID := bundle.Identities["alice"]
	if alice.Password != aliceID.EffectivePassword("alice") {
		t.Errorf("alice password: got %q, want %q", alice.Password, aliceID.EffectivePassword("alice"))
	}
	if alice.ClientID != aliceID.EffectiveClientID("alice") {
		t.Errorf("alice client_id: got %q, want %q", alice.ClientID, aliceID.EffectiveClientID("alice"))
	}
	if alice.ClientSecret != aliceID.EffectiveClientSecret("alice") {
		t.Errorf("alice client_secret: got %q, want %q", alice.ClientSecret, aliceID.EffectiveClientSecret("alice"))
	}

	// Custom claims: scalar.
	if alice.CustomClaims["clearance"] != "top-secret" {
		t.Errorf("alice clearance claim: got %v, want %q", alice.CustomClaims["clearance"], "top-secret")
	}

	// Custom claims: array.
	wantGroups := []string{"eng", "ops"}
	gotGroups, ok := alice.CustomClaims["groups"].([]string)
	if !ok {
		t.Fatalf("alice groups claim: expected []string, got %T", alice.CustomClaims["groups"])
	}
	if !reflect.DeepEqual(gotGroups, wantGroups) {
		t.Errorf("alice groups claim: got %v, want %v", gotGroups, wantGroups)
	}

	// Bob has scalar claim only.
	if bob.CustomClaims["clearance"] != "secret" {
		t.Errorf("bob clearance claim: got %v, want %q", bob.CustomClaims["clearance"], "secret")
	}
	if _, hasGroups := bob.CustomClaims["groups"]; hasGroups {
		t.Error("bob should not have groups claim")
	}
}

func TestGenerateIdentitiesDefaults(t *testing.T) {
	// Minimal identity: no password, client_id, or client_secret overrides.
	bundle := identityTestBundle(map[string]Identity{
		"user1": {
			Claims: map[string]interface{}{
				"clearance": "secret",
			},
		},
	})

	out, err := GenerateIdentities(bundle)
	if err != nil {
		t.Fatalf("GenerateIdentities error: %v", err)
	}

	if len(out.Users) != 1 {
		t.Fatalf("expected 1 user, got %d", len(out.Users))
	}

	user := out.Users[0]

	// Default password: "{name}-secret"
	if user.Password != "user1-secret" {
		t.Errorf("password: got %q, want %q", user.Password, "user1-secret")
	}

	// Default client_id: "{name}-client"
	if user.ClientID != "user1-client" {
		t.Errorf("client_id: got %q, want %q", user.ClientID, "user1-client")
	}

	// Default client_secret: "{name}-secret"
	if user.ClientSecret != "user1-secret" {
		t.Errorf("client_secret: got %q, want %q", user.ClientSecret, "user1-secret")
	}

	// Default role: standard (non-admin).
	wantRoles := []string{"opentdf-standard"}
	if !reflect.DeepEqual(user.Roles, wantRoles) {
		t.Errorf("roles: got %v, want %v", user.Roles, wantRoles)
	}

	// Username is set to the identity name.
	if user.Username != "user1" {
		t.Errorf("username: got %q, want %q", user.Username, "user1")
	}

	// Subject ID is deterministic.
	if user.SubjectID != "00000000-0000-0000-0000-000000000010" {
		t.Errorf("subject_id: got %q, want %q", user.SubjectID, "00000000-0000-0000-0000-000000000010")
	}
}

func TestGenerateIdentitiesCustomCredentials(t *testing.T) {
	bundle := identityTestBundle(map[string]Identity{
		"svc": {
			Claims:       map[string]interface{}{"clearance": "top-secret"},
			Password:     "custom-pw",
			ClientID:     "custom-client",
			ClientSecret: "custom-secret",
			Admin:        true,
		},
	})

	out, err := GenerateIdentities(bundle)
	if err != nil {
		t.Fatalf("GenerateIdentities error: %v", err)
	}

	if len(out.Users) != 1 {
		t.Fatalf("expected 1 user, got %d", len(out.Users))
	}

	user := out.Users[0]

	if user.Password != "custom-pw" {
		t.Errorf("password: got %q, want %q", user.Password, "custom-pw")
	}
	if user.ClientID != "custom-client" {
		t.Errorf("client_id: got %q, want %q", user.ClientID, "custom-client")
	}
	if user.ClientSecret != "custom-secret" {
		t.Errorf("client_secret: got %q, want %q", user.ClientSecret, "custom-secret")
	}

	// Admin role should be present.
	wantRoles := []string{"opentdf-admin", "opentdf-standard"}
	if !reflect.DeepEqual(user.Roles, wantRoles) {
		t.Errorf("roles: got %v, want %v", user.Roles, wantRoles)
	}
}

func TestGenerateIdentitiesBuiltIn(t *testing.T) {
	// Even with an empty identities map, built-in accounts should be present.
	bundle := identityTestBundle(map[string]Identity{
		"minimal": {
			Claims: map[string]interface{}{"clearance": "unclassified"},
		},
	})

	out, err := GenerateIdentities(bundle)
	if err != nil {
		t.Fatalf("GenerateIdentities error: %v", err)
	}

	if len(out.Clients) != 2 {
		t.Fatalf("expected 2 built-in clients, got %d", len(out.Clients))
	}

	// Find opentdf and opentdf-sdk by client_id.
	var foundOpentdf, foundSDK bool
	for _, c := range out.Clients {
		switch c.ClientID {
		case "opentdf":
			foundOpentdf = true
			if c.ClientSecret != "secret" {
				t.Errorf("opentdf client_secret: got %q, want %q", c.ClientSecret, "secret")
			}
			wantRoles := []string{"opentdf-admin", "opentdf-standard"}
			if !reflect.DeepEqual(c.Roles, wantRoles) {
				t.Errorf("opentdf roles: got %v, want %v", c.Roles, wantRoles)
			}
			if c.SubjectID != "00000000-0000-0000-0000-000000000003" {
				t.Errorf("opentdf subject_id: got %q, want %q", c.SubjectID, "00000000-0000-0000-0000-000000000003")
			}

		case "opentdf-sdk":
			foundSDK = true
			if c.ClientSecret != "secret" {
				t.Errorf("opentdf-sdk client_secret: got %q, want %q", c.ClientSecret, "secret")
			}
			wantRoles := []string{"opentdf-standard"}
			if !reflect.DeepEqual(c.Roles, wantRoles) {
				t.Errorf("opentdf-sdk roles: got %v, want %v", c.Roles, wantRoles)
			}
			if c.SubjectID != "00000000-0000-0000-0000-000000000002" {
				t.Errorf("opentdf-sdk subject_id: got %q, want %q", c.SubjectID, "00000000-0000-0000-0000-000000000002")
			}
		}
	}

	if !foundOpentdf {
		t.Error("missing built-in opentdf client")
	}
	if !foundSDK {
		t.Error("missing built-in opentdf-sdk client")
	}

	// Verify built-in accounts have no username/password (they are client-only).
	for _, c := range out.Clients {
		if c.Username != "" {
			t.Errorf("built-in client %q should have no username, got %q", c.ClientID, c.Username)
		}
		if c.Password != "" {
			t.Errorf("built-in client %q should have no password, got %q", c.ClientID, c.Password)
		}
	}
}

func TestGenerateIdentitiesNilBundle(t *testing.T) {
	_, err := GenerateIdentities(nil)
	if err == nil {
		t.Fatal("expected error for nil bundle, got nil")
	}
}

func TestGenerateIdentitiesEmptyIdentities(t *testing.T) {
	bundle := identityTestBundle(map[string]Identity{})

	out, err := GenerateIdentities(bundle)
	if err != nil {
		t.Fatalf("GenerateIdentities error: %v", err)
	}

	// No user identities, but built-in clients still present.
	if len(out.Users) != 0 {
		t.Errorf("expected 0 users, got %d", len(out.Users))
	}
	if len(out.Clients) != 2 {
		t.Errorf("expected 2 built-in clients, got %d", len(out.Clients))
	}
}

func TestGenerateIdentitiesNoClaims(t *testing.T) {
	// Identity with no claims should produce nil CustomClaims.
	bundle := identityTestBundle(map[string]Identity{
		"noclaims": {},
	})

	out, err := GenerateIdentities(bundle)
	if err != nil {
		t.Fatalf("GenerateIdentities error: %v", err)
	}

	if len(out.Users) != 1 {
		t.Fatalf("expected 1 user, got %d", len(out.Users))
	}

	user := out.Users[0]
	if user.CustomClaims != nil {
		t.Errorf("expected nil CustomClaims for identity with no claims, got %v", user.CustomClaims)
	}
}
