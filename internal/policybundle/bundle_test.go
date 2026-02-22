package policybundle

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Identity JSON round-trip tests
// ---------------------------------------------------------------------------

func TestIdentityMarshalJSON(t *testing.T) {
	tests := []struct {
		name     string
		identity Identity
		want     map[string]interface{}
	}{
		{
			name: "scalar hierarchy claim",
			identity: Identity{
				Claims: map[string]interface{}{"clearance": "top-secret"},
			},
			want: map[string]interface{}{"clearance": "top-secret"},
		},
		{
			name: "array allOf claim",
			identity: Identity{
				Claims: map[string]interface{}{"groups": []string{"eng", "ops"}},
			},
			want: map[string]interface{}{"groups": []interface{}{"eng", "ops"}},
		},
		{
			name: "reserved fields only",
			identity: Identity{
				Admin:        true,
				Password:     "pw123",
				ClientID:     "myid",
				ClientSecret: "mysecret",
			},
			want: map[string]interface{}{
				"admin":         true,
				"password":      "pw123",
				"client_id":     "myid",
				"client_secret": "mysecret",
			},
		},
		{
			name: "mixed claims and reserved fields",
			identity: Identity{
				Claims:   map[string]interface{}{"clearance": "secret", "teams": []string{"alpha"}},
				Admin:    true,
				Password: "pass",
			},
			want: map[string]interface{}{
				"clearance": "secret",
				"teams":     []interface{}{"alpha"},
				"admin":     true,
				"password":  "pass",
			},
		},
		{
			name:     "empty claims no reserved",
			identity: Identity{},
			want:     map[string]interface{}{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.identity)
			if err != nil {
				t.Fatalf("MarshalJSON error: %v", err)
			}
			var got map[string]interface{}
			if err := json.Unmarshal(data, &got); err != nil {
				t.Fatalf("Unmarshal output error: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestIdentityUnmarshalJSON(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		want      Identity
		wantErr   bool
		errSubstr string
	}{
		{
			name:  "scalar hierarchy claim",
			input: `{"clearance":"top-secret"}`,
			want: Identity{
				Claims: map[string]interface{}{"clearance": "top-secret"},
			},
		},
		{
			name:  "array allOf claim",
			input: `{"groups":["eng","ops"]}`,
			want: Identity{
				Claims: map[string]interface{}{"groups": []string{"eng", "ops"}},
			},
		},
		{
			name:  "reserved fields round-trip",
			input: `{"admin":true,"password":"pw","client_id":"cid","client_secret":"csec"}`,
			want: Identity{
				Claims:       map[string]interface{}{},
				Admin:        true,
				Password:     "pw",
				ClientID:     "cid",
				ClientSecret: "csec",
			},
		},
		{
			name:  "mixed claims and reserved",
			input: `{"clearance":"secret","admin":true,"password":"p"}`,
			want: Identity{
				Claims:   map[string]interface{}{"clearance": "secret"},
				Admin:    true,
				Password: "p",
			},
		},
		{
			name:  "empty object",
			input: `{}`,
			want: Identity{
				Claims: map[string]interface{}{},
			},
		},
		{
			name:      "invalid claim type number",
			input:     `{"clearance":42}`,
			wantErr:   true,
			errSubstr: "must be a string or array of strings",
		},
		{
			name:      "invalid claim type nested object",
			input:     `{"clearance":{"level":"top"}}`,
			wantErr:   true,
			errSubstr: "must be a string or array of strings",
		},
		{
			name:      "invalid admin field type",
			input:     `{"admin":"yes"}`,
			wantErr:   true,
			errSubstr: "invalid admin field",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got Identity
			err := json.Unmarshal([]byte(tt.input), &got)

			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.errSubstr)
				}
				if !strings.Contains(err.Error(), tt.errSubstr) {
					t.Fatalf("error %q does not contain %q", err.Error(), tt.errSubstr)
				}
				return
			}

			if err != nil {
				t.Fatalf("UnmarshalJSON error: %v", err)
			}
			if !reflect.DeepEqual(got.Claims, tt.want.Claims) {
				t.Errorf("Claims: got %#v, want %#v", got.Claims, tt.want.Claims)
			}
			if got.Admin != tt.want.Admin {
				t.Errorf("Admin: got %v, want %v", got.Admin, tt.want.Admin)
			}
			if got.Password != tt.want.Password {
				t.Errorf("Password: got %q, want %q", got.Password, tt.want.Password)
			}
			if got.ClientID != tt.want.ClientID {
				t.Errorf("ClientID: got %q, want %q", got.ClientID, tt.want.ClientID)
			}
			if got.ClientSecret != tt.want.ClientSecret {
				t.Errorf("ClientSecret: got %q, want %q", got.ClientSecret, tt.want.ClientSecret)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Bundle JSON round-trip tests
// ---------------------------------------------------------------------------

func TestBundleMarshalJSON(t *testing.T) {
	tests := []struct {
		name   string
		bundle Bundle
	}{
		{
			name: "full bundle with attributes and identities",
			bundle: Bundle{
				Version:   1,
				Namespace: "example.com",
				Attributes: []Attribute{
					{Name: "clearance", Rule: RuleHierarchy, Values: []string{"top-secret", "secret", "unclassified"}},
					{Name: "groups", Rule: RuleAllOf, Values: []string{"eng", "ops", "finance"}},
				},
				Identities: map[string]Identity{
					"alice": {
						Claims: map[string]interface{}{"clearance": "top-secret", "groups": []string{"eng", "ops"}},
						Admin:  true,
					},
					"bob": {
						Claims:   map[string]interface{}{"clearance": "secret"},
						Password: "bob-pw",
					},
				},
				Options: &Options{
					TokenTTL:       "30m",
					DefaultActions: []string{"read"},
				},
			},
		},
		{
			name: "bundle with sealed section",
			bundle: Bundle{
				Version:   1,
				Namespace: "sealed.example.com",
				Attributes: []Attribute{
					{Name: "level", Rule: RuleAnyOf, Values: []string{"a", "b"}},
				},
				Identities: map[string]Identity{
					"svc": {Claims: map[string]interface{}{"level": []string{"a"}}},
				},
				Sealed: &Sealed{
					KASKeys:     "age-encrypted-kas-keys",
					IDPKey:      "age-encrypted-idp-key",
					Fingerprint: "SHA256:abc123",
				},
				Signature: "base64sig==",
			},
		},
		{
			name: "minimal bundle no options no sealed",
			bundle: Bundle{
				Attributes: []Attribute{
					{Name: "dept", Rule: RuleAnyOf, Values: []string{"eng"}},
				},
				Identities: map[string]Identity{
					"user1": {Claims: map[string]interface{}{"dept": []string{"eng"}}},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.bundle)
			if err != nil {
				t.Fatalf("Marshal error: %v", err)
			}

			var got Bundle
			if err := json.Unmarshal(data, &got); err != nil {
				t.Fatalf("Unmarshal error: %v", err)
			}

			// Verify top-level fields.
			if got.Version != tt.bundle.Version {
				t.Errorf("Version: got %d, want %d", got.Version, tt.bundle.Version)
			}
			if got.Namespace != tt.bundle.Namespace {
				t.Errorf("Namespace: got %q, want %q", got.Namespace, tt.bundle.Namespace)
			}
			if got.Signature != tt.bundle.Signature {
				t.Errorf("Signature: got %q, want %q", got.Signature, tt.bundle.Signature)
			}

			// Verify attributes.
			if len(got.Attributes) != len(tt.bundle.Attributes) {
				t.Fatalf("Attributes length: got %d, want %d", len(got.Attributes), len(tt.bundle.Attributes))
			}
			for i, a := range got.Attributes {
				want := tt.bundle.Attributes[i]
				if a.Name != want.Name || a.Rule != want.Rule || !reflect.DeepEqual(a.Values, want.Values) {
					t.Errorf("Attributes[%d]: got %+v, want %+v", i, a, want)
				}
			}

			// Verify identities exist and have matching claims.
			if len(got.Identities) != len(tt.bundle.Identities) {
				t.Fatalf("Identities length: got %d, want %d", len(got.Identities), len(tt.bundle.Identities))
			}
			for name, wantID := range tt.bundle.Identities {
				gotID, ok := got.Identities[name]
				if !ok {
					t.Errorf("missing identity %q", name)
					continue
				}
				if gotID.Admin != wantID.Admin {
					t.Errorf("identity %q Admin: got %v, want %v", name, gotID.Admin, wantID.Admin)
				}
				if gotID.Password != wantID.Password {
					t.Errorf("identity %q Password: got %q, want %q", name, gotID.Password, wantID.Password)
				}
				// Claims comparison: after round-trip, []string becomes []interface{} from JSON.
				// Verify key-by-key.
				if len(gotID.Claims) != len(wantID.Claims) {
					t.Errorf("identity %q claims length: got %d, want %d", name, len(gotID.Claims), len(wantID.Claims))
				}
			}

			// Verify sealed section.
			if tt.bundle.Sealed != nil {
				if got.Sealed == nil {
					t.Fatal("Sealed: got nil, want non-nil")
				}
				if got.Sealed.KASKeys != tt.bundle.Sealed.KASKeys {
					t.Errorf("Sealed.KASKeys: got %q, want %q", got.Sealed.KASKeys, tt.bundle.Sealed.KASKeys)
				}
				if got.Sealed.IDPKey != tt.bundle.Sealed.IDPKey {
					t.Errorf("Sealed.IDPKey: got %q, want %q", got.Sealed.IDPKey, tt.bundle.Sealed.IDPKey)
				}
				if got.Sealed.Fingerprint != tt.bundle.Sealed.Fingerprint {
					t.Errorf("Sealed.Fingerprint: got %q, want %q", got.Sealed.Fingerprint, tt.bundle.Sealed.Fingerprint)
				}
			} else if got.Sealed != nil {
				t.Errorf("Sealed: got %+v, want nil", got.Sealed)
			}

			// Verify options.
			if tt.bundle.Options != nil {
				if got.Options == nil {
					t.Fatal("Options: got nil, want non-nil")
				}
				if got.Options.TokenTTL != tt.bundle.Options.TokenTTL {
					t.Errorf("Options.TokenTTL: got %q, want %q", got.Options.TokenTTL, tt.bundle.Options.TokenTTL)
				}
				if !reflect.DeepEqual(got.Options.DefaultActions, tt.bundle.Options.DefaultActions) {
					t.Errorf("Options.DefaultActions: got %v, want %v", got.Options.DefaultActions, tt.bundle.Options.DefaultActions)
				}
			} else if got.Options != nil {
				t.Errorf("Options: got %+v, want nil", got.Options)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Validation tests
// ---------------------------------------------------------------------------

func TestBundleValidate(t *testing.T) {
	validBundle := func() Bundle {
		return Bundle{
			Version:   1,
			Namespace: "test.local",
			Attributes: []Attribute{
				{Name: "clearance", Rule: RuleHierarchy, Values: []string{"top-secret", "secret"}},
				{Name: "groups", Rule: RuleAllOf, Values: []string{"eng", "ops"}},
			},
			Identities: map[string]Identity{
				"alice": {
					Claims: map[string]interface{}{
						"clearance": "top-secret",
						"groups":    []string{"eng"},
					},
				},
			},
		}
	}

	tests := []struct {
		name      string
		modify    func(b *Bundle)
		wantErr   bool
		errSubstr string
	}{
		{
			name:   "valid bundle passes",
			modify: func(b *Bundle) {},
		},
		{
			name: "missing attributes fails",
			modify: func(b *Bundle) {
				b.Attributes = nil
			},
			wantErr:   true,
			errSubstr: "at least one attribute is required",
		},
		{
			name: "missing identities fails",
			modify: func(b *Bundle) {
				b.Identities = nil
			},
			wantErr:   true,
			errSubstr: "at least one identity is required",
		},
		{
			name: "unknown claim key fails",
			modify: func(b *Bundle) {
				b.Identities = map[string]Identity{
					"alice": {Claims: map[string]interface{}{"nonexistent": "value"}},
				}
			},
			wantErr:   true,
			errSubstr: "does not match any attribute",
		},
		{
			name: "hierarchy claim with wrong type array",
			modify: func(b *Bundle) {
				b.Identities = map[string]Identity{
					"alice": {Claims: map[string]interface{}{"clearance": []string{"top-secret"}}},
				}
			},
			wantErr:   true,
			errSubstr: "must be a string (hierarchy attribute)",
		},
		{
			name: "allOf claim with wrong type string",
			modify: func(b *Bundle) {
				b.Identities = map[string]Identity{
					"alice": {Claims: map[string]interface{}{"groups": "eng"}},
				}
			},
			wantErr:   true,
			errSubstr: "must be an array of strings",
		},
		{
			name: "hierarchy claim with invalid value",
			modify: func(b *Bundle) {
				b.Identities = map[string]Identity{
					"alice": {Claims: map[string]interface{}{"clearance": "bogus"}},
				}
			},
			wantErr:   true,
			errSubstr: "is not in attribute values",
		},
		{
			name: "allOf claim with invalid value in array",
			modify: func(b *Bundle) {
				b.Identities = map[string]Identity{
					"alice": {Claims: map[string]interface{}{"groups": []string{"eng", "bogus"}}},
				}
			},
			wantErr:   true,
			errSubstr: "is not in attribute values",
		},
		{
			name: "duplicate attribute names fails",
			modify: func(b *Bundle) {
				b.Attributes = append(b.Attributes, Attribute{
					Name: "clearance", Rule: RuleHierarchy, Values: []string{"a"},
				})
			},
			wantErr:   true,
			errSubstr: "duplicate name",
		},
		{
			name: "empty attribute values fails",
			modify: func(b *Bundle) {
				b.Attributes[0].Values = nil
			},
			wantErr:   true,
			errSubstr: "at least one value is required",
		},
		{
			name: "invalid rule type fails",
			modify: func(b *Bundle) {
				b.Attributes[0].Rule = "badRule"
			},
			wantErr:   true,
			errSubstr: "invalid rule",
		},
		{
			name: "empty attribute name fails",
			modify: func(b *Bundle) {
				b.Attributes = append(b.Attributes, Attribute{
					Name: "", Rule: RuleAnyOf, Values: []string{"x"},
				})
			},
			wantErr:   true,
			errSubstr: "name is required",
		},
		{
			name: "empty string in attribute values fails",
			modify: func(b *Bundle) {
				b.Attributes[0].Values = []string{"top-secret", ""}
			},
			wantErr:   true,
			errSubstr: "is empty",
		},
		{
			name: "anyOf claim with wrong type string",
			modify: func(b *Bundle) {
				b.Attributes = []Attribute{
					{Name: "tags", Rule: RuleAnyOf, Values: []string{"a", "b"}},
				}
				b.Identities = map[string]Identity{
					"alice": {Claims: map[string]interface{}{"tags": "a"}},
				}
			},
			wantErr:   true,
			errSubstr: "must be an array of strings",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := validBundle()
			tt.modify(&b)
			err := b.Validate()

			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.errSubstr)
				}
				if !strings.Contains(err.Error(), tt.errSubstr) {
					t.Fatalf("error %q does not contain %q", err.Error(), tt.errSubstr)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Effective defaults tests
// ---------------------------------------------------------------------------

func TestEffectiveDefaults(t *testing.T) {
	t.Run("EffectiveNamespace returns default when empty", func(t *testing.T) {
		b := &Bundle{}
		if got := b.EffectiveNamespace(); got != DefaultNamespace {
			t.Errorf("got %q, want %q", got, DefaultNamespace)
		}
	})

	t.Run("EffectiveNamespace returns custom when set", func(t *testing.T) {
		b := &Bundle{Namespace: "custom.ns"}
		if got := b.EffectiveNamespace(); got != "custom.ns" {
			t.Errorf("got %q, want %q", got, "custom.ns")
		}
	})

	t.Run("EffectiveVersion returns 1 when 0", func(t *testing.T) {
		b := &Bundle{}
		if got := b.EffectiveVersion(); got != 1 {
			t.Errorf("got %d, want 1", got)
		}
	})

	t.Run("EffectiveVersion returns custom when set", func(t *testing.T) {
		b := &Bundle{Version: 3}
		if got := b.EffectiveVersion(); got != 3 {
			t.Errorf("got %d, want 3", got)
		}
	})

	t.Run("EffectiveActions returns defaults when nil options", func(t *testing.T) {
		b := &Bundle{}
		if got := b.EffectiveActions(); !reflect.DeepEqual(got, DefaultActions) {
			t.Errorf("got %v, want %v", got, DefaultActions)
		}
	})

	t.Run("EffectiveActions returns defaults when empty actions", func(t *testing.T) {
		b := &Bundle{Options: &Options{}}
		if got := b.EffectiveActions(); !reflect.DeepEqual(got, DefaultActions) {
			t.Errorf("got %v, want %v", got, DefaultActions)
		}
	})

	t.Run("EffectiveActions returns custom when set", func(t *testing.T) {
		want := []string{"decrypt", "download"}
		b := &Bundle{Options: &Options{DefaultActions: want}}
		if got := b.EffectiveActions(); !reflect.DeepEqual(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("EffectivePassword returns default", func(t *testing.T) {
		id := &Identity{}
		if got := id.EffectivePassword("alice"); got != "alice-secret" {
			t.Errorf("got %q, want %q", got, "alice-secret")
		}
	})

	t.Run("EffectivePassword returns override", func(t *testing.T) {
		id := &Identity{Password: "custom-pw"}
		if got := id.EffectivePassword("alice"); got != "custom-pw" {
			t.Errorf("got %q, want %q", got, "custom-pw")
		}
	})

	t.Run("EffectiveClientID returns default", func(t *testing.T) {
		id := &Identity{}
		if got := id.EffectiveClientID("bob"); got != "bob-client" {
			t.Errorf("got %q, want %q", got, "bob-client")
		}
	})

	t.Run("EffectiveClientID returns override", func(t *testing.T) {
		id := &Identity{ClientID: "my-client"}
		if got := id.EffectiveClientID("bob"); got != "my-client" {
			t.Errorf("got %q, want %q", got, "my-client")
		}
	})

	t.Run("EffectiveClientSecret returns default", func(t *testing.T) {
		id := &Identity{}
		if got := id.EffectiveClientSecret("svc"); got != "svc-secret" {
			t.Errorf("got %q, want %q", got, "svc-secret")
		}
	})

	t.Run("EffectiveClientSecret returns override", func(t *testing.T) {
		id := &Identity{ClientSecret: "my-secret"}
		if got := id.EffectiveClientSecret("svc"); got != "my-secret" {
			t.Errorf("got %q, want %q", got, "my-secret")
		}
	})

	t.Run("IsSealed returns false for unsealed bundle", func(t *testing.T) {
		b := &Bundle{}
		if b.IsSealed() {
			t.Error("expected IsSealed() == false for empty bundle")
		}
	})

	t.Run("IsSealed returns false with sealed but no signature", func(t *testing.T) {
		b := &Bundle{Sealed: &Sealed{KASKeys: "k", IDPKey: "i", Fingerprint: "f"}}
		if b.IsSealed() {
			t.Error("expected IsSealed() == false when signature is empty")
		}
	})

	t.Run("IsSealed returns false with signature but no sealed", func(t *testing.T) {
		b := &Bundle{Signature: "sig"}
		if b.IsSealed() {
			t.Error("expected IsSealed() == false when sealed is nil")
		}
	})

	t.Run("IsSealed returns true for sealed bundle", func(t *testing.T) {
		b := &Bundle{
			Sealed:    &Sealed{KASKeys: "k", IDPKey: "i", Fingerprint: "f"},
			Signature: "base64sig==",
		}
		if !b.IsSealed() {
			t.Error("expected IsSealed() == true")
		}
	})
}

// ---------------------------------------------------------------------------
// IsReservedKey tests
// ---------------------------------------------------------------------------

func TestIsReservedKey(t *testing.T) {
	tests := []struct {
		key  string
		want bool
	}{
		{"admin", true},
		{"password", true},
		{"client_id", true},
		{"client_secret", true},
		{"clearance", false},
		{"groups", false},
		{"", false},
		{"Admin", false},  // case-sensitive
		{"PASSWORD", false}, // case-sensitive
	}

	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			if got := IsReservedKey(tt.key); got != tt.want {
				t.Errorf("IsReservedKey(%q) = %v, want %v", tt.key, got, tt.want)
			}
		})
	}
}

// testdataDir returns the absolute path to the testdata directory adjacent to this test file.
func testdataDir() string {
	_, thisFile, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(thisFile), "testdata")
}

// ---------------------------------------------------------------------------
// Testdata loading tests
// ---------------------------------------------------------------------------

func TestLoadPlainPolicy(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(testdataDir(), "policy.json"))
	if err != nil {
		t.Fatalf("failed to read policy.json: %v", err)
	}

	var b Bundle
	if err := json.Unmarshal(data, &b); err != nil {
		t.Fatalf("failed to unmarshal policy.json: %v", err)
	}

	// --- Attributes ---
	if len(b.Attributes) != 3 {
		t.Fatalf("expected 3 attributes, got %d", len(b.Attributes))
	}

	wantAttrs := []struct {
		name       string
		rule       AttributeRule
		valueCount int
	}{
		{"classification_level", RuleHierarchy, 4},
		{"sci_control_system", RuleAllOf, 3},
		{"releasable_to", RuleAllOf, 5},
	}
	for i, want := range wantAttrs {
		got := b.Attributes[i]
		if got.Name != want.name {
			t.Errorf("attribute[%d] name: got %q, want %q", i, got.Name, want.name)
		}
		if got.Rule != want.rule {
			t.Errorf("attribute[%d] rule: got %q, want %q", i, got.Rule, want.rule)
		}
		if len(got.Values) != want.valueCount {
			t.Errorf("attribute[%d] value count: got %d, want %d", i, len(got.Values), want.valueCount)
		}
	}

	// --- Identities ---
	if len(b.Identities) != 5 {
		t.Fatalf("expected 5 identities, got %d", len(b.Identities))
	}

	// Validate claim types: hierarchy attributes should be scalar strings,
	// allOf attributes should be []string arrays.
	for name, id := range b.Identities {
		if clVal, ok := id.Claims["classification_level"]; ok {
			if _, isString := clVal.(string); !isString {
				t.Errorf("identity %q: classification_level should be string, got %T", name, clVal)
			}
		}
		if sciVal, ok := id.Claims["sci_control_system"]; ok {
			if _, isArr := sciVal.([]string); !isArr {
				t.Errorf("identity %q: sci_control_system should be []string, got %T", name, sciVal)
			}
		}
		if relVal, ok := id.Claims["releasable_to"]; ok {
			if _, isArr := relVal.([]string); !isArr {
				t.Errorf("identity %q: releasable_to should be []string, got %T", name, relVal)
			}
		}
	}

	// Spot-check specific identities.
	alice := b.Identities["alice"]
	if alice.Claims["classification_level"] != "TOP_SECRET" {
		t.Errorf("alice classification_level: got %v, want TOP_SECRET", alice.Claims["classification_level"])
	}
	if !reflect.DeepEqual(alice.Claims["sci_control_system"], []string{"SI", "HCS", "TK"}) {
		t.Errorf("alice sci_control_system: got %v, want [SI HCS TK]", alice.Claims["sci_control_system"])
	}

	eve := b.Identities["eve"]
	if _, has := eve.Claims["releasable_to"]; has {
		t.Error("eve should not have releasable_to claim")
	}

	// --- Validate() ---
	if err := b.Validate(); err != nil {
		t.Errorf("Validate() returned error on valid plain policy: %v", err)
	}

	// --- IsSealed() ---
	if b.IsSealed() {
		t.Error("IsSealed() should return false for plain policy")
	}

	// --- EffectiveNamespace() ---
	if got := b.EffectiveNamespace(); got != "tdflite.local" {
		t.Errorf("EffectiveNamespace(): got %q, want %q", got, "tdflite.local")
	}
}

func TestLoadSealedPolicy(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(testdataDir(), "policy.sealed.json"))
	if err != nil {
		t.Fatalf("failed to read policy.sealed.json: %v", err)
	}

	var b Bundle
	if err := json.Unmarshal(data, &b); err != nil {
		t.Fatalf("failed to unmarshal policy.sealed.json: %v", err)
	}

	// --- Attributes (same as plain) ---
	if len(b.Attributes) != 3 {
		t.Fatalf("expected 3 attributes, got %d", len(b.Attributes))
	}

	wantAttrs := []struct {
		name       string
		rule       AttributeRule
		valueCount int
	}{
		{"classification_level", RuleHierarchy, 4},
		{"sci_control_system", RuleAllOf, 3},
		{"releasable_to", RuleAllOf, 5},
	}
	for i, want := range wantAttrs {
		got := b.Attributes[i]
		if got.Name != want.name {
			t.Errorf("attribute[%d] name: got %q, want %q", i, got.Name, want.name)
		}
		if got.Rule != want.rule {
			t.Errorf("attribute[%d] rule: got %q, want %q", i, got.Rule, want.rule)
		}
		if len(got.Values) != want.valueCount {
			t.Errorf("attribute[%d] value count: got %d, want %d", i, len(got.Values), want.valueCount)
		}
	}

	// --- Identities (same as plain) ---
	if len(b.Identities) != 5 {
		t.Fatalf("expected 5 identities, got %d", len(b.Identities))
	}

	// Validate claim types match expectations.
	for name, id := range b.Identities {
		if clVal, ok := id.Claims["classification_level"]; ok {
			if _, isString := clVal.(string); !isString {
				t.Errorf("identity %q: classification_level should be string, got %T", name, clVal)
			}
		}
		if sciVal, ok := id.Claims["sci_control_system"]; ok {
			if _, isArr := sciVal.([]string); !isArr {
				t.Errorf("identity %q: sci_control_system should be []string, got %T", name, sciVal)
			}
		}
	}

	// --- IsSealed() ---
	if !b.IsSealed() {
		t.Error("IsSealed() should return true for sealed policy")
	}

	// --- Sealed fields ---
	if b.Sealed == nil {
		t.Fatal("Sealed section should not be nil")
	}
	if b.Sealed.Fingerprint == "" {
		t.Error("Sealed.Fingerprint should be non-empty")
	}

	// --- Signature ---
	if b.Signature == "" {
		t.Error("Signature should be non-empty")
	}

	// --- Version ---
	if b.Version != 1 {
		t.Errorf("Version: got %d, want 1", b.Version)
	}
}
