// Package policybundle defines the sealed policy bundle schema for TDFLite.
//
// A policy bundle is a single JSON file that contains everything needed to boot
// a TDFLite instance: attribute definitions, identity assignments, and (when
// sealed) encrypted KAS keys. Combined with an SSH key, one file replaces all
// config, provisioning scripts, and manual setup.
//
// Lifecycle:
//
//	Author  →  policy.json        (plain, human-editable)
//	Seal    →  policy.sealed.json (signed, KAS keys encrypted with SSH pubkey)
//	Boot    →  tdflite serve --policy policy.sealed.json --key ~/.ssh/id_ed25519
package policybundle

import (
	"encoding/json"
	"fmt"
	"strings"
)

// DefaultNamespace is used when the bundle omits the namespace field.
const DefaultNamespace = "tdflite.local"

// DefaultActions applied to all auto-generated subject mappings.
var DefaultActions = []string{"read", "create"}

// AttributeRule defines how an attribute's values are evaluated during access decisions.
type AttributeRule string

const (
	// RuleHierarchy means the user's level must be >= the data's level.
	// Values are ordered: first = highest clearance.
	RuleHierarchy AttributeRule = "hierarchy"

	// RuleAllOf means the user must possess ALL values tagged on the data.
	RuleAllOf AttributeRule = "allOf"

	// RuleAnyOf means the user must possess AT LEAST ONE value tagged on the data.
	RuleAnyOf AttributeRule = "anyOf"
)

// Bundle is the top-level policy bundle. It can represent both a plain
// (unsealed) policy file and a sealed file with encrypted keys and a signature.
type Bundle struct {
	// Version is the schema version. Currently must be 1.
	Version int `json:"version,omitempty"`

	// Namespace for attribute FQNs. Default: "tdflite.local".
	// Attributes become: https://{namespace}/attr/{name}/value/{value}
	Namespace string `json:"namespace,omitempty"`

	// Attributes defines the policy attributes and their allowed values.
	Attributes []Attribute `json:"attributes"`

	// Identities maps usernames to their attribute claims.
	Identities map[string]Identity `json:"identities"`

	// Options holds optional overrides for power users.
	Options *Options `json:"options,omitempty"`

	// Sealed contains encrypted key material, present only after sealing.
	Sealed *Sealed `json:"sealed,omitempty"`

	// Signature is a base64-encoded signature over all fields except itself.
	// Present only after sealing.
	Signature string `json:"signature,omitempty"`
}

// EffectiveNamespace returns the namespace to use, falling back to the default.
func (b *Bundle) EffectiveNamespace() string {
	if b.Namespace != "" {
		return b.Namespace
	}
	return DefaultNamespace
}

// EffectiveVersion returns the version, defaulting to 1.
func (b *Bundle) EffectiveVersion() int {
	if b.Version > 0 {
		return b.Version
	}
	return 1
}

// EffectiveActions returns the actions to use for subject mappings.
func (b *Bundle) EffectiveActions() []string {
	if b.Options != nil && len(b.Options.DefaultActions) > 0 {
		return b.Options.DefaultActions
	}
	return DefaultActions
}

// IsSealed reports whether this bundle has been sealed.
func (b *Bundle) IsSealed() bool {
	return b.Sealed != nil && b.Signature != ""
}

// Attribute defines a policy attribute with its rule and allowed values.
type Attribute struct {
	// Name is the attribute identifier. Becomes part of the FQN.
	Name string `json:"name"`

	// Rule determines how values are evaluated: "hierarchy", "allOf", or "anyOf".
	Rule AttributeRule `json:"rule"`

	// Values lists the allowed values. For hierarchy rules, order matters:
	// first element = highest level.
	Values []string `json:"values"`
}

// Identity represents a user/service account and their attribute claims.
// Claim keys must match attribute names defined in the bundle.
//
// Claims are stored as a map: scalar string values (for hierarchy attributes)
// or string arrays (for allOf/anyOf attributes). The Admin, Password, ClientID,
// and ClientSecret fields are extracted from reserved keys during unmarshaling.
type Identity struct {
	// Claims maps attribute names to their values.
	// Hierarchy attributes → single string value.
	// allOf/anyOf attributes → []string value.
	Claims map[string]interface{} `json:"-"`

	// Admin grants the admin role when true. Default: false.
	Admin bool `json:"admin,omitempty"`

	// Password overrides the default "{name}-secret" password.
	Password string `json:"password,omitempty"`

	// ClientID overrides the default "{name}-client" client ID.
	ClientID string `json:"client_id,omitempty"`

	// ClientSecret overrides the default "{name}-secret" client secret.
	ClientSecret string `json:"client_secret,omitempty"`
}

// reservedKeys are identity JSON keys that are not attribute claims.
var reservedKeys = map[string]bool{
	"admin":         true,
	"password":      true,
	"client_id":     true,
	"client_secret": true,
}

// MarshalJSON produces a flat JSON object where claims are top-level keys
// alongside the reserved fields (admin, password, client_id, client_secret).
func (id Identity) MarshalJSON() ([]byte, error) {
	m := make(map[string]interface{})

	// Write claims as top-level keys.
	for k, v := range id.Claims {
		m[k] = v
	}

	// Write reserved fields only if non-zero.
	if id.Admin {
		m["admin"] = true
	}
	if id.Password != "" {
		m["password"] = id.Password
	}
	if id.ClientID != "" {
		m["client_id"] = id.ClientID
	}
	if id.ClientSecret != "" {
		m["client_secret"] = id.ClientSecret
	}

	return json.Marshal(m)
}

// UnmarshalJSON parses a flat JSON object, extracting reserved fields and
// treating everything else as attribute claims.
func (id *Identity) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	id.Claims = make(map[string]interface{})

	for key, val := range raw {
		switch key {
		case "admin":
			if err := json.Unmarshal(val, &id.Admin); err != nil {
				return fmt.Errorf("invalid admin field: %w", err)
			}
		case "password":
			if err := json.Unmarshal(val, &id.Password); err != nil {
				return fmt.Errorf("invalid password field: %w", err)
			}
		case "client_id":
			if err := json.Unmarshal(val, &id.ClientID); err != nil {
				return fmt.Errorf("invalid client_id field: %w", err)
			}
		case "client_secret":
			if err := json.Unmarshal(val, &id.ClientSecret); err != nil {
				return fmt.Errorf("invalid client_secret field: %w", err)
			}
		default:
			// Try string first, then []string.
			var s string
			if err := json.Unmarshal(val, &s); err == nil {
				id.Claims[key] = s
				continue
			}
			var arr []string
			if err := json.Unmarshal(val, &arr); err == nil {
				id.Claims[key] = arr
				continue
			}
			return fmt.Errorf("claim %q: must be a string or array of strings", key)
		}
	}

	return nil
}

// EffectivePassword returns the password, defaulting to "{name}-secret".
func (id *Identity) EffectivePassword(name string) string {
	if id.Password != "" {
		return id.Password
	}
	return name + "-secret"
}

// EffectiveClientID returns the client ID, defaulting to "{name}-client".
func (id *Identity) EffectiveClientID(name string) string {
	if id.ClientID != "" {
		return id.ClientID
	}
	return name + "-client"
}

// EffectiveClientSecret returns the client secret, defaulting to "{name}-secret".
func (id *Identity) EffectiveClientSecret(name string) string {
	if id.ClientSecret != "" {
		return id.ClientSecret
	}
	return name + "-secret"
}

// Sealed holds encrypted key material. Present only in sealed bundles.
//
// Two sealing modes are supported:
//   - SSH key mode (recommended): keys encrypted with an SSH public key via age.
//     The Fingerprint field identifies which SSH key can unseal.
//   - Passphrase mode: keys encrypted with a passphrase-derived key via age/scrypt.
//     The Fingerprint field is empty and Method is set to "passphrase".
type Sealed struct {
	// KASKeys contains age-encrypted RSA + EC private keys for the KAS.
	KASKeys string `json:"kas_keys"`

	// IDPKey contains the age-encrypted IdP signing key.
	IDPKey string `json:"idp_key"`

	// Fingerprint is the SSH public key fingerprint (e.g. "SHA256:xxxx")
	// used to encrypt the keys. Empty when sealed with a passphrase.
	Fingerprint string `json:"fingerprint,omitempty"`

	// Method is the sealing method: "ssh" (default) or "passphrase".
	// Omitted in JSON when empty (defaults to "ssh" for backward compat).
	Method string `json:"method,omitempty"`
}

// Options holds optional overrides for power users.
type Options struct {
	// TokenTTL overrides the default token time-to-live (e.g. "10m", "1h").
	TokenTTL string `json:"token_ttl,omitempty"`

	// DefaultActions overrides the actions applied to subject mappings.
	// Default: ["read", "create"]
	DefaultActions []string `json:"default_actions,omitempty"`
}

// Validate checks the bundle for structural correctness:
//   - At least one attribute with at least one value
//   - At least one identity
//   - All identity claims reference defined attributes
//   - Hierarchy claims are scalar strings matching an attribute value
//   - allOf/anyOf claims are string arrays with all elements in the attribute's values
//   - No duplicate attribute names
//   - No empty attribute values
//   - Valid rule types
func (b *Bundle) Validate() error {
	var errs []string

	if len(b.Attributes) == 0 {
		errs = append(errs, "at least one attribute is required")
	}
	if len(b.Identities) == 0 {
		errs = append(errs, "at least one identity is required")
	}

	// Build attribute lookup.
	attrByName := make(map[string]*Attribute, len(b.Attributes))
	attrNames := make(map[string]bool, len(b.Attributes))
	for i := range b.Attributes {
		a := &b.Attributes[i]

		if a.Name == "" {
			errs = append(errs, fmt.Sprintf("attribute[%d]: name is required", i))
			continue
		}
		if attrNames[a.Name] {
			errs = append(errs, fmt.Sprintf("attribute %q: duplicate name", a.Name))
			continue
		}
		attrNames[a.Name] = true

		switch a.Rule {
		case RuleHierarchy, RuleAllOf, RuleAnyOf:
			// valid
		default:
			errs = append(errs, fmt.Sprintf("attribute %q: invalid rule %q (must be hierarchy, allOf, or anyOf)", a.Name, a.Rule))
		}

		if len(a.Values) == 0 {
			errs = append(errs, fmt.Sprintf("attribute %q: at least one value is required", a.Name))
		}
		for j, v := range a.Values {
			if v == "" {
				errs = append(errs, fmt.Sprintf("attribute %q: values[%d] is empty", a.Name, j))
			}
		}

		attrByName[a.Name] = a
	}

	// Validate identities.
	for name, id := range b.Identities {
		for claimKey, claimVal := range id.Claims {
			if reservedKeys[claimKey] {
				errs = append(errs, fmt.Sprintf("identity %q: %q is a reserved field, not a claim", name, claimKey))
				continue
			}

			attr, ok := attrByName[claimKey]
			if !ok {
				errs = append(errs, fmt.Sprintf("identity %q: claim %q does not match any attribute", name, claimKey))
				continue
			}

			valueSet := make(map[string]bool, len(attr.Values))
			for _, v := range attr.Values {
				valueSet[v] = true
			}

			switch attr.Rule {
			case RuleHierarchy:
				// Must be a scalar string.
				s, ok := claimVal.(string)
				if !ok {
					errs = append(errs, fmt.Sprintf("identity %q: claim %q must be a string (hierarchy attribute)", name, claimKey))
					continue
				}
				if !valueSet[s] {
					errs = append(errs, fmt.Sprintf("identity %q: claim %q value %q is not in attribute values %v", name, claimKey, s, attr.Values))
				}

			case RuleAllOf, RuleAnyOf:
				// Must be an array of strings.
				arr, ok := claimVal.([]string)
				if !ok {
					errs = append(errs, fmt.Sprintf("identity %q: claim %q must be an array of strings (%s attribute)", name, claimKey, attr.Rule))
					continue
				}
				for _, v := range arr {
					if !valueSet[v] {
						errs = append(errs, fmt.Sprintf("identity %q: claim %q value %q is not in attribute values %v", name, claimKey, v, attr.Values))
					}
				}
			}
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("policy bundle validation failed:\n  - %s", strings.Join(errs, "\n  - "))
	}
	return nil
}

// IsReservedKey reports whether a key name is reserved and cannot be used as a claim.
func IsReservedKey(key string) bool {
	return reservedKeys[key]
}
