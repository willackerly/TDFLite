package tests_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/willackerly/TDFLite/internal/policybundle"
	"golang.org/x/crypto/ssh"
)

// ---------------------------------------------------------------------------
// Helper: build a rich bundle, generate Ed25519 SSH keypair, seal + sign
// ---------------------------------------------------------------------------

// sealAndSign creates a rich policy bundle programmatically (3 attributes,
// 4 identities, options, custom namespace), generates a temp Ed25519 SSH
// keypair, seals with the SSH public key, signs with the SSH private key,
// and returns the bundle plus key paths.
func sealAndSign(t *testing.T) (*policybundle.Bundle, string, string) {
	t.Helper()

	bundle := &policybundle.Bundle{
		Version:   1,
		Namespace: "tamper-test.example.com",
		Attributes: []policybundle.Attribute{
			{
				Name: "classification",
				Rule: policybundle.RuleHierarchy,
				Values: []string{
					"TOP_SECRET", "SECRET", "CONFIDENTIAL", "UNCLASSIFIED",
				},
			},
			{
				Name:   "compartments",
				Rule:   policybundle.RuleAllOf,
				Values: []string{"ALPHA", "BRAVO", "CHARLIE"},
			},
			{
				Name:   "releasable_to",
				Rule:   policybundle.RuleAnyOf,
				Values: []string{"USA", "GBR", "CAN"},
			},
		},
		Identities: map[string]policybundle.Identity{
			"alice": {
				Claims: map[string]interface{}{
					"classification": "TOP_SECRET",
					"compartments":   []string{"ALPHA", "BRAVO", "CHARLIE"},
					"releasable_to":  []string{"USA", "GBR", "CAN"},
				},
				Admin:    true,
				Password: "alice-pass",
			},
			"bob": {
				Claims: map[string]interface{}{
					"classification": "SECRET",
					"compartments":   []string{"ALPHA"},
					"releasable_to":  []string{"USA"},
				},
				ClientID:     "bob-custom-client",
				ClientSecret: "bob-custom-secret",
			},
			"carol": {
				Claims: map[string]interface{}{
					"classification": "CONFIDENTIAL",
					"compartments":   []string{"ALPHA", "BRAVO"},
					"releasable_to":  []string{"USA", "GBR"},
				},
			},
			"dave": {
				Claims: map[string]interface{}{
					"classification": "UNCLASSIFIED",
					"releasable_to":  []string{"USA"},
				},
			},
		},
		Options: &policybundle.Options{
			TokenTTL:       "15m",
			DefaultActions: []string{"read", "create", "update"},
		},
	}

	// Generate Ed25519 SSH keypair.
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

	// Seal with SSH key.
	if err := policybundle.SealWithSSHKey(bundle, pubPath); err != nil {
		t.Fatalf("SealWithSSHKey: %v", err)
	}

	// Sign with SSH private key.
	if err := policybundle.SignBundle(bundle, privPath); err != nil {
		t.Fatalf("SignBundle: %v", err)
	}

	return bundle, pubPath, privPath
}

// cloneViaJSON round-trips a bundle through JSON to get a deep copy.
// This is how an attacker would work: modify the JSON file on disk.
func cloneViaJSON(t *testing.T, bundle *policybundle.Bundle) *policybundle.Bundle {
	t.Helper()
	data, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("marshal for clone: %v", err)
	}
	var clone policybundle.Bundle
	if err := json.Unmarshal(data, &clone); err != nil {
		t.Fatalf("unmarshal for clone: %v", err)
	}
	return &clone
}

// tamperViaMap marshals to JSON, unmarshals into map[string]interface{},
// applies a mutation function, then marshals back and unmarshals into Bundle.
// This simulates raw JSON-level tampering.
func tamperViaMap(t *testing.T, bundle *policybundle.Bundle, mutate func(m map[string]interface{})) *policybundle.Bundle {
	t.Helper()
	data, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("marshal for tamper: %v", err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal to map: %v", err)
	}
	mutate(m)
	data2, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal tampered map: %v", err)
	}
	var tampered policybundle.Bundle
	if err := json.Unmarshal(data2, &tampered); err != nil {
		t.Fatalf("unmarshal tampered bundle: %v", err)
	}
	return &tampered
}

// getAttrSlice extracts the attributes array from a map[string]interface{}.
func getAttrSlice(m map[string]interface{}) []interface{} {
	return m["attributes"].([]interface{})
}

// getAttr extracts the i-th attribute as a map.
func getAttr(m map[string]interface{}, i int) map[string]interface{} {
	return getAttrSlice(m)[i].(map[string]interface{})
}

// getIdentities extracts the identities map.
func getIdentities(m map[string]interface{}) map[string]interface{} {
	return m["identities"].(map[string]interface{})
}

// getIdentity extracts a named identity as a map.
func getIdentity(m map[string]interface{}, name string) map[string]interface{} {
	return getIdentities(m)[name].(map[string]interface{})
}

// getSealed extracts the sealed section as a map.
func getSealed(m map[string]interface{}) map[string]interface{} {
	return m["sealed"].(map[string]interface{})
}

// getOptions extracts the options section as a map, or nil.
func getOptions(m map[string]interface{}) map[string]interface{} {
	if o, ok := m["options"]; ok && o != nil {
		return o.(map[string]interface{})
	}
	return nil
}

// ---------------------------------------------------------------------------
// TestTamperDetectionExhaustive
// ---------------------------------------------------------------------------

func TestTamperDetectionExhaustive(t *testing.T) {
	tests := []struct {
		name   string
		tamper func(t *testing.T, original *policybundle.Bundle) *policybundle.Bundle
	}{
		// ---- Attribute tampering ----
		{
			name: "attribute/change_name",
			tamper: func(t *testing.T, b *policybundle.Bundle) *policybundle.Bundle {
				return tamperViaMap(t, b, func(m map[string]interface{}) {
					getAttr(m, 0)["name"] = "clearance"
				})
			},
		},
		{
			name: "attribute/change_rule",
			tamper: func(t *testing.T, b *policybundle.Bundle) *policybundle.Bundle {
				return tamperViaMap(t, b, func(m map[string]interface{}) {
					getAttr(m, 0)["rule"] = "allOf"
				})
			},
		},
		{
			name: "attribute/add_value",
			tamper: func(t *testing.T, b *policybundle.Bundle) *policybundle.Bundle {
				return tamperViaMap(t, b, func(m map[string]interface{}) {
					attr := getAttr(m, 0)
					vals := attr["values"].([]interface{})
					attr["values"] = append(vals, "ULTRA")
				})
			},
		},
		{
			name: "attribute/remove_value",
			tamper: func(t *testing.T, b *policybundle.Bundle) *policybundle.Bundle {
				return tamperViaMap(t, b, func(m map[string]interface{}) {
					attr := getAttr(m, 0)
					vals := attr["values"].([]interface{})
					attr["values"] = vals[:len(vals)-1]
				})
			},
		},
		{
			name: "attribute/change_value",
			tamper: func(t *testing.T, b *policybundle.Bundle) *policybundle.Bundle {
				return tamperViaMap(t, b, func(m map[string]interface{}) {
					attr := getAttr(m, 0)
					vals := attr["values"].([]interface{})
					vals[0] = "ULTRA"
				})
			},
		},
		{
			name: "attribute/reorder_values",
			tamper: func(t *testing.T, b *policybundle.Bundle) *policybundle.Bundle {
				return tamperViaMap(t, b, func(m map[string]interface{}) {
					attr := getAttr(m, 0)
					vals := attr["values"].([]interface{})
					// Reverse the values: [TOP_SECRET, SECRET, CONFIDENTIAL, UNCLASSIFIED]
					// becomes [UNCLASSIFIED, CONFIDENTIAL, SECRET, TOP_SECRET]
					for i, j := 0, len(vals)-1; i < j; i, j = i+1, j-1 {
						vals[i], vals[j] = vals[j], vals[i]
					}
				})
			},
		},
		{
			name: "attribute/add_new_attribute",
			tamper: func(t *testing.T, b *policybundle.Bundle) *policybundle.Bundle {
				return tamperViaMap(t, b, func(m map[string]interface{}) {
					attrs := getAttrSlice(m)
					newAttr := map[string]interface{}{
						"name":   "injected",
						"rule":   "anyOf",
						"values": []interface{}{"X", "Y"},
					}
					m["attributes"] = append(attrs, newAttr)
				})
			},
		},
		{
			name: "attribute/remove_attribute",
			tamper: func(t *testing.T, b *policybundle.Bundle) *policybundle.Bundle {
				return tamperViaMap(t, b, func(m map[string]interface{}) {
					attrs := getAttrSlice(m)
					m["attributes"] = attrs[:len(attrs)-1]
				})
			},
		},
		{
			name: "attribute/empty_values",
			tamper: func(t *testing.T, b *policybundle.Bundle) *policybundle.Bundle {
				return tamperViaMap(t, b, func(m map[string]interface{}) {
					getAttr(m, 1)["values"] = []interface{}{}
				})
			},
		},

		// ---- Identity tampering ----
		{
			name: "identity/change_scalar_claim",
			tamper: func(t *testing.T, b *policybundle.Bundle) *policybundle.Bundle {
				return tamperViaMap(t, b, func(m map[string]interface{}) {
					getIdentity(m, "alice")["classification"] = "SECRET"
				})
			},
		},
		{
			name: "identity/add_element_to_array_claim",
			tamper: func(t *testing.T, b *policybundle.Bundle) *policybundle.Bundle {
				return tamperViaMap(t, b, func(m map[string]interface{}) {
					alice := getIdentity(m, "alice")
					comp := alice["compartments"].([]interface{})
					alice["compartments"] = append(comp, "DELTA")
				})
			},
		},
		{
			name: "identity/remove_element_from_array_claim",
			tamper: func(t *testing.T, b *policybundle.Bundle) *policybundle.Bundle {
				return tamperViaMap(t, b, func(m map[string]interface{}) {
					alice := getIdentity(m, "alice")
					comp := alice["compartments"].([]interface{})
					alice["compartments"] = comp[:len(comp)-1]
				})
			},
		},
		{
			name: "identity/add_new_identity",
			tamper: func(t *testing.T, b *policybundle.Bundle) *policybundle.Bundle {
				return tamperViaMap(t, b, func(m map[string]interface{}) {
					ids := getIdentities(m)
					ids["mallory"] = map[string]interface{}{
						"classification": "TOP_SECRET",
						"admin":          true,
					}
				})
			},
		},
		{
			name: "identity/remove_identity",
			tamper: func(t *testing.T, b *policybundle.Bundle) *policybundle.Bundle {
				return tamperViaMap(t, b, func(m map[string]interface{}) {
					ids := getIdentities(m)
					delete(ids, "dave")
				})
			},
		},
		{
			name: "identity/change_admin_false_to_true",
			tamper: func(t *testing.T, b *policybundle.Bundle) *policybundle.Bundle {
				return tamperViaMap(t, b, func(m map[string]interface{}) {
					getIdentity(m, "bob")["admin"] = true
				})
			},
		},
		{
			name: "identity/add_admin_flag",
			tamper: func(t *testing.T, b *policybundle.Bundle) *policybundle.Bundle {
				return tamperViaMap(t, b, func(m map[string]interface{}) {
					// carol has no admin flag; inject one
					getIdentity(m, "carol")["admin"] = true
				})
			},
		},
		{
			name: "identity/change_password",
			tamper: func(t *testing.T, b *policybundle.Bundle) *policybundle.Bundle {
				return tamperViaMap(t, b, func(m map[string]interface{}) {
					getIdentity(m, "alice")["password"] = "hacked-pass"
				})
			},
		},
		{
			name: "identity/change_client_id",
			tamper: func(t *testing.T, b *policybundle.Bundle) *policybundle.Bundle {
				return tamperViaMap(t, b, func(m map[string]interface{}) {
					getIdentity(m, "bob")["client_id"] = "evil-client"
				})
			},
		},
		{
			name: "identity/change_client_secret",
			tamper: func(t *testing.T, b *policybundle.Bundle) *policybundle.Bundle {
				return tamperViaMap(t, b, func(m map[string]interface{}) {
					getIdentity(m, "bob")["client_secret"] = "evil-secret"
				})
			},
		},

		// ---- Sealed section tampering ----
		{
			name: "sealed/modify_kas_keys_blob",
			tamper: func(t *testing.T, b *policybundle.Bundle) *policybundle.Bundle {
				clone := cloneViaJSON(t, b)
				// Flip a character in the middle of the encrypted blob.
				kas := clone.Sealed.KASKeys
				mid := len(kas) / 2
				if kas[mid] == 'A' {
					clone.Sealed.KASKeys = kas[:mid] + "B" + kas[mid+1:]
				} else {
					clone.Sealed.KASKeys = kas[:mid] + "A" + kas[mid+1:]
				}
				return clone
			},
		},
		{
			name: "sealed/modify_idp_key_blob",
			tamper: func(t *testing.T, b *policybundle.Bundle) *policybundle.Bundle {
				clone := cloneViaJSON(t, b)
				idp := clone.Sealed.IDPKey
				mid := len(idp) / 2
				if idp[mid] == 'Z' {
					clone.Sealed.IDPKey = idp[:mid] + "Y" + idp[mid+1:]
				} else {
					clone.Sealed.IDPKey = idp[:mid] + "Z" + idp[mid+1:]
				}
				return clone
			},
		},
		{
			name: "sealed/modify_fingerprint",
			tamper: func(t *testing.T, b *policybundle.Bundle) *policybundle.Bundle {
				clone := cloneViaJSON(t, b)
				clone.Sealed.Fingerprint = "SHA256:tamperedfingerprint"
				return clone
			},
		},
		{
			name: "sealed/change_method",
			tamper: func(t *testing.T, b *policybundle.Bundle) *policybundle.Bundle {
				clone := cloneViaJSON(t, b)
				clone.Sealed.Method = "passphrase"
				return clone
			},
		},

		// ---- Top-level field tampering ----
		{
			name: "toplevel/change_version",
			tamper: func(t *testing.T, b *policybundle.Bundle) *policybundle.Bundle {
				clone := cloneViaJSON(t, b)
				clone.Version = 2
				return clone
			},
		},
		{
			name: "toplevel/change_namespace",
			tamper: func(t *testing.T, b *policybundle.Bundle) *policybundle.Bundle {
				clone := cloneViaJSON(t, b)
				clone.Namespace = "evil.example.com"
				return clone
			},
		},
		{
			name: "toplevel/add_namespace",
			tamper: func(t *testing.T, b *policybundle.Bundle) *policybundle.Bundle {
				// Create a bundle without namespace, seal it, then inject one.
				return tamperViaMap(t, b, func(m map[string]interface{}) {
					// The original has a namespace; change it to something else
					// to simulate injection of a different namespace.
					m["namespace"] = "injected.example.com"
				})
			},
		},
		{
			name: "toplevel/remove_namespace",
			tamper: func(t *testing.T, b *policybundle.Bundle) *policybundle.Bundle {
				return tamperViaMap(t, b, func(m map[string]interface{}) {
					delete(m, "namespace")
				})
			},
		},

		// ---- Options tampering ----
		{
			name: "options/change_token_ttl",
			tamper: func(t *testing.T, b *policybundle.Bundle) *policybundle.Bundle {
				clone := cloneViaJSON(t, b)
				clone.Options.TokenTTL = "24h"
				return clone
			},
		},
		{
			name: "options/change_default_actions",
			tamper: func(t *testing.T, b *policybundle.Bundle) *policybundle.Bundle {
				clone := cloneViaJSON(t, b)
				clone.Options.DefaultActions = []string{"read", "create", "update", "delete"}
				return clone
			},
		},
		{
			name: "options/remove_options",
			tamper: func(t *testing.T, b *policybundle.Bundle) *policybundle.Bundle {
				return tamperViaMap(t, b, func(m map[string]interface{}) {
					delete(m, "options")
				})
			},
		},
		{
			name: "options/add_options_where_none_existed",
			tamper: func(t *testing.T, b *policybundle.Bundle) *policybundle.Bundle {
				// First build a bundle with no options by tampering the map.
				// But since our original has options, we simulate by changing
				// the options content to something different.
				return tamperViaMap(t, b, func(m map[string]interface{}) {
					m["options"] = map[string]interface{}{
						"token_ttl":       "999h",
						"default_actions": []interface{}{"admin"},
					}
				})
			},
		},

		// ---- Signature tampering ----
		{
			name: "signature/truncate",
			tamper: func(t *testing.T, b *policybundle.Bundle) *policybundle.Bundle {
				clone := cloneViaJSON(t, b)
				sig := clone.Signature
				clone.Signature = sig[:len(sig)-1]
				return clone
			},
		},
		{
			name: "signature/change_one_char",
			tamper: func(t *testing.T, b *policybundle.Bundle) *policybundle.Bundle {
				clone := cloneViaJSON(t, b)
				sig := []byte(clone.Signature)
				// Change the 10th character.
				if sig[10] == 'A' {
					sig[10] = 'B'
				} else {
					sig[10] = 'A'
				}
				clone.Signature = string(sig)
				return clone
			},
		},
		{
			name: "signature/empty",
			tamper: func(t *testing.T, b *policybundle.Bundle) *policybundle.Bundle {
				clone := cloneViaJSON(t, b)
				clone.Signature = ""
				return clone
			},
		},
		{
			name: "signature/from_different_bundle",
			tamper: func(t *testing.T, b *policybundle.Bundle) *policybundle.Bundle {
				// Get a signature from a completely different bundle.
				otherBundle, _, _ := sealAndSign(t)
				clone := cloneViaJSON(t, b)
				clone.Signature = otherBundle.Signature
				return clone
			},
		},

		// ---- Edge cases ----
		{
			name: "edge/swap_identity_claims",
			tamper: func(t *testing.T, b *policybundle.Bundle) *policybundle.Bundle {
				return tamperViaMap(t, b, func(m map[string]interface{}) {
					ids := getIdentities(m)
					alice := ids["alice"].(map[string]interface{})
					bob := ids["bob"].(map[string]interface{})

					// Swap their classification claims.
					aliceClass := alice["classification"]
					bobClass := bob["classification"]
					alice["classification"] = bobClass
					bob["classification"] = aliceClass

					// Swap their compartments claims.
					aliceComp := alice["compartments"]
					bobComp := bob["compartments"]
					alice["compartments"] = bobComp
					bob["compartments"] = aliceComp
				})
			},
		},
		{
			name: "edge/trailing_space_in_string",
			tamper: func(t *testing.T, b *policybundle.Bundle) *policybundle.Bundle {
				return tamperViaMap(t, b, func(m map[string]interface{}) {
					getIdentity(m, "alice")["classification"] = "TOP_SECRET "
				})
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			original, pubPath, _ := sealAndSign(t)

			// Verify the original is valid before tampering.
			if err := policybundle.VerifySignature(original, pubPath); err != nil {
				t.Fatalf("original bundle should verify: %v", err)
			}

			// Apply tampering.
			tampered := tc.tamper(t, original)

			// Verification must fail on the tampered bundle.
			err := policybundle.VerifySignature(tampered, pubPath)
			if err == nil {
				// Marshal tampered bundle for debugging output.
				tamperedJSON, _ := json.MarshalIndent(tampered, "", "  ")
				origJSON, _ := json.MarshalIndent(original, "", "  ")
				t.Fatalf("expected VerifySignature to FAIL on tampered bundle, but it succeeded.\n"+
					"Tamper case: %s\n"+
					"Original JSON length: %d\n"+
					"Tampered JSON length: %d\n"+
					"Tampered JSON (first 500 chars): %s\n"+
					"Original JSON (first 500 chars): %s",
					tc.name,
					len(origJSON), len(tamperedJSON),
					truncate(string(tamperedJSON), 500),
					truncate(string(origJSON), 500))
			}
			t.Logf("tamper case %q correctly detected: %v", tc.name, err)
		})
	}
}

// truncate returns at most n characters of s.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// ---------------------------------------------------------------------------
// TestTamperDetectionPassphraseMode
// ---------------------------------------------------------------------------

func TestTamperDetectionPassphraseMode(t *testing.T) {
	buildPassphraseBundle := func(t *testing.T) *policybundle.Bundle {
		t.Helper()
		bundle := &policybundle.Bundle{
			Version:   1,
			Namespace: "passphrase-test.local",
			Attributes: []policybundle.Attribute{
				{
					Name:   "level",
					Rule:   policybundle.RuleHierarchy,
					Values: []string{"HIGH", "MEDIUM", "LOW"},
				},
				{
					Name:   "groups",
					Rule:   policybundle.RuleAllOf,
					Values: []string{"ENG", "OPS", "SEC"},
				},
			},
			Identities: map[string]policybundle.Identity{
				"admin": {
					Claims: map[string]interface{}{
						"level":  "HIGH",
						"groups": []string{"ENG", "OPS", "SEC"},
					},
					Admin: true,
				},
				"user1": {
					Claims: map[string]interface{}{
						"level":  "MEDIUM",
						"groups": []string{"ENG"},
					},
				},
			},
		}

		passphrase := "tamper-test-passphrase-2024"
		if err := policybundle.SealWithPassphrase(bundle, passphrase); err != nil {
			t.Fatalf("SealWithPassphrase: %v", err)
		}
		if err := policybundle.SignBundlePassphrase(bundle); err != nil {
			t.Fatalf("SignBundlePassphrase: %v", err)
		}
		return bundle
	}

	tests := []struct {
		name   string
		tamper func(t *testing.T, b *policybundle.Bundle) *policybundle.Bundle
	}{
		{
			name: "change_attribute_value",
			tamper: func(t *testing.T, b *policybundle.Bundle) *policybundle.Bundle {
				return tamperViaMap(t, b, func(m map[string]interface{}) {
					attr := getAttr(m, 0)
					vals := attr["values"].([]interface{})
					vals[0] = "ULTRA"
				})
			},
		},
		{
			name: "change_identity_claim",
			tamper: func(t *testing.T, b *policybundle.Bundle) *policybundle.Bundle {
				return tamperViaMap(t, b, func(m map[string]interface{}) {
					getIdentity(m, "user1")["level"] = "HIGH"
				})
			},
		},
		{
			name: "modify_sealed_blob",
			tamper: func(t *testing.T, b *policybundle.Bundle) *policybundle.Bundle {
				clone := cloneViaJSON(t, b)
				kas := clone.Sealed.KASKeys
				mid := len(kas) / 2
				if kas[mid] == 'X' {
					clone.Sealed.KASKeys = kas[:mid] + "Y" + kas[mid+1:]
				} else {
					clone.Sealed.KASKeys = kas[:mid] + "X" + kas[mid+1:]
				}
				return clone
			},
		},
		{
			name: "add_identity",
			tamper: func(t *testing.T, b *policybundle.Bundle) *policybundle.Bundle {
				return tamperViaMap(t, b, func(m map[string]interface{}) {
					ids := getIdentities(m)
					ids["attacker"] = map[string]interface{}{
						"level": "HIGH",
						"admin": true,
					}
				})
			},
		},
		{
			name: "change_admin_flag",
			tamper: func(t *testing.T, b *policybundle.Bundle) *policybundle.Bundle {
				return tamperViaMap(t, b, func(m map[string]interface{}) {
					getIdentity(m, "user1")["admin"] = true
				})
			},
		},
		{
			name: "change_namespace",
			tamper: func(t *testing.T, b *policybundle.Bundle) *policybundle.Bundle {
				clone := cloneViaJSON(t, b)
				clone.Namespace = "evil.local"
				return clone
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			original := buildPassphraseBundle(t)

			// Verify original is valid.
			if err := policybundle.VerifyPassphraseSignature(original); err != nil {
				t.Fatalf("original passphrase bundle should verify: %v", err)
			}

			tampered := tc.tamper(t, original)

			err := policybundle.VerifyPassphraseSignature(tampered)
			if err == nil {
				t.Fatalf("expected VerifyPassphraseSignature to FAIL on tampered bundle, but it succeeded (case: %s)", tc.name)
			}
			t.Logf("passphrase tamper case %q correctly detected: %v", tc.name, err)
		})
	}
}

// ---------------------------------------------------------------------------
// TestCrossModeTamper
// ---------------------------------------------------------------------------

func TestCrossModeTamper(t *testing.T) {
	t.Run("ssh_bundle_with_passphrase_verify", func(t *testing.T) {
		// Seal + sign with SSH key.
		bundle, _, _ := sealAndSign(t)

		// Try to verify with passphrase mode -- should fail because the
		// SSH signature is not a SHA-256 hash.
		err := policybundle.VerifyPassphraseSignature(bundle)
		if err == nil {
			t.Fatal("expected VerifyPassphraseSignature to FAIL on SSH-signed bundle, but it succeeded")
		}
		t.Logf("cross-mode (SSH -> passphrase verify) correctly detected: %v", err)
	})

	t.Run("passphrase_bundle_with_ssh_verify", func(t *testing.T) {
		// Build a passphrase-sealed bundle.
		bundle := &policybundle.Bundle{
			Version:   1,
			Namespace: "cross-test.local",
			Attributes: []policybundle.Attribute{
				{Name: "level", Rule: policybundle.RuleHierarchy, Values: []string{"A", "B", "C"}},
			},
			Identities: map[string]policybundle.Identity{
				"user": {Claims: map[string]interface{}{"level": "A"}},
			},
		}

		passphrase := "cross-test-passphrase"
		if err := policybundle.SealWithPassphrase(bundle, passphrase); err != nil {
			t.Fatalf("SealWithPassphrase: %v", err)
		}
		if err := policybundle.SignBundlePassphrase(bundle); err != nil {
			t.Fatalf("SignBundlePassphrase: %v", err)
		}

		// Generate a random SSH key and try to verify with it.
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("generating ed25519 key: %v", err)
		}
		dir := t.TempDir()
		sshPub, err := ssh.NewPublicKey(pub)
		if err != nil {
			t.Fatalf("creating SSH public key: %v", err)
		}
		pubPath := filepath.Join(dir, "id_ed25519.pub")
		if err := os.WriteFile(pubPath, ssh.MarshalAuthorizedKey(sshPub), 0644); err != nil {
			t.Fatalf("writing public key: %v", err)
		}

		err = policybundle.VerifySignature(bundle, pubPath)
		if err == nil {
			t.Fatal("expected VerifySignature (SSH) to FAIL on passphrase-signed bundle, but it succeeded")
		}
		t.Logf("cross-mode (passphrase -> SSH verify) correctly detected: %v", err)
	})
}

// ---------------------------------------------------------------------------
// TestTamperDetectionNoOptionsBundle
// ---------------------------------------------------------------------------

// TestTamperDetectionNoOptionsBundle tests adding options to a bundle that
// was originally sealed without any options, ensuring the signature detects it.
func TestTamperDetectionNoOptionsBundle(t *testing.T) {
	// Build a bundle with NO options.
	bundle := &policybundle.Bundle{
		Version:   1,
		Namespace: "no-opts.local",
		Attributes: []policybundle.Attribute{
			{Name: "level", Rule: policybundle.RuleHierarchy, Values: []string{"HIGH", "LOW"}},
		},
		Identities: map[string]policybundle.Identity{
			"user": {Claims: map[string]interface{}{"level": "HIGH"}},
		},
		// Options intentionally nil.
	}

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

	if err := policybundle.SealWithSSHKey(bundle, pubPath); err != nil {
		t.Fatalf("SealWithSSHKey: %v", err)
	}
	if err := policybundle.SignBundle(bundle, privPath); err != nil {
		t.Fatalf("SignBundle: %v", err)
	}

	// Verify original is valid.
	if err := policybundle.VerifySignature(bundle, pubPath); err != nil {
		t.Fatalf("original should verify: %v", err)
	}

	// Tamper: inject options into a bundle that had none.
	tampered := tamperViaMap(t, bundle, func(m map[string]interface{}) {
		m["options"] = map[string]interface{}{
			"token_ttl":       "999h",
			"default_actions": []interface{}{"admin"},
		}
	})

	err = policybundle.VerifySignature(tampered, pubPath)
	if err == nil {
		t.Fatal("expected VerifySignature to FAIL after injecting options into no-options bundle, but it succeeded")
	}
	t.Logf("no-options tamper correctly detected: %v", err)
}

// ---------------------------------------------------------------------------
// TestTamperDetectionNoNamespaceBundle
// ---------------------------------------------------------------------------

// TestTamperDetectionNoNamespaceBundle tests adding a namespace to a bundle
// that was originally sealed without one.
func TestTamperDetectionNoNamespaceBundle(t *testing.T) {
	// Build a bundle with NO namespace (uses default).
	bundle := &policybundle.Bundle{
		Version: 1,
		// Namespace intentionally empty (uses default "tdflite.local").
		Attributes: []policybundle.Attribute{
			{Name: "level", Rule: policybundle.RuleHierarchy, Values: []string{"HIGH", "LOW"}},
		},
		Identities: map[string]policybundle.Identity{
			"user": {Claims: map[string]interface{}{"level": "HIGH"}},
		},
	}

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

	if err := policybundle.SealWithSSHKey(bundle, pubPath); err != nil {
		t.Fatalf("SealWithSSHKey: %v", err)
	}
	if err := policybundle.SignBundle(bundle, privPath); err != nil {
		t.Fatalf("SignBundle: %v", err)
	}

	// Verify original is valid.
	if err := policybundle.VerifySignature(bundle, pubPath); err != nil {
		t.Fatalf("original should verify: %v", err)
	}

	// Tamper: add namespace to a bundle that had none.
	tampered := tamperViaMap(t, bundle, func(m map[string]interface{}) {
		m["namespace"] = "injected.example.com"
	})

	err = policybundle.VerifySignature(tampered, pubPath)
	if err == nil {
		t.Fatal("expected VerifySignature to FAIL after injecting namespace into no-namespace bundle, but it succeeded")
	}
	t.Logf("no-namespace tamper correctly detected: %v", err)
}

// ---------------------------------------------------------------------------
// TestTamperDetectionJSONStringReplace
// ---------------------------------------------------------------------------

// TestTamperDetectionJSONStringReplace tests tampering via raw string
// replacement on the JSON bytes (most realistic attack scenario: the attacker
// modifies the .sealed.json file with a text editor).
func TestTamperDetectionJSONStringReplace(t *testing.T) {
	original, pubPath, _ := sealAndSign(t)

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	tests := []struct {
		name    string
		oldStr  string
		newStr  string
	}{
		{"replace_TOP_SECRET_with_ULTRA", "TOP_SECRET", "ULTRA_XTRA"},
		{"replace_alice_with_admin", `"alice"`, `"admin"`},
		{"replace_hierarchy_with_anyOf", "hierarchy", "anyOf"},
		{"replace_namespace", "tamper-test.example.com", "hacked.example.com"},
		{"replace_compartments_value", "ALPHA", "OMEGA"},
		{"replace_true_admin_to_false", `"admin":true`, `"admin":false`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tamperedJSON := strings.Replace(string(data), tc.oldStr, tc.newStr, 1)
			if tamperedJSON == string(data) {
				t.Skipf("string %q not found in JSON, skipping", tc.oldStr)
			}

			var tampered policybundle.Bundle
			if err := json.Unmarshal([]byte(tamperedJSON), &tampered); err != nil {
				t.Fatalf("unmarshal tampered JSON: %v", err)
			}

			err := policybundle.VerifySignature(&tampered, pubPath)
			if err == nil {
				t.Fatalf("expected VerifySignature to FAIL after replacing %q with %q, but it succeeded", tc.oldStr, tc.newStr)
			}
			t.Logf("JSON string replace %q -> %q correctly detected: %v", tc.oldStr, tc.newStr, err)
		})
	}
}
