package templates

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"github.com/willackerly/TDFLite/internal/policybundle"
	"golang.org/x/crypto/ssh"
)

func init() {
	policybundle.SetSealWorkFactor(10)
}

// writeSSHKeyPair generates an Ed25519 SSH keypair and writes it to temp files.
// Returns (pubKeyPath, privKeyPath).
func writeSSHKeyPair(t *testing.T) (string, string) {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating ed25519 key: %v", err)
	}

	privPEM, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatalf("marshaling private key: %v", err)
	}

	dir := t.TempDir()
	privPath := filepath.Join(dir, "id_ed25519")
	if err := os.WriteFile(privPath, pem.EncodeToMemory(privPEM), 0600); err != nil {
		t.Fatalf("writing private key: %v", err)
	}

	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("creating SSH public key: %v", err)
	}
	pubBytes := ssh.MarshalAuthorizedKey(sshPub)

	pubPath := filepath.Join(dir, "id_ed25519.pub")
	if err := os.WriteFile(pubPath, pubBytes, 0644); err != nil {
		t.Fatalf("writing public key: %v", err)
	}

	return pubPath, privPath
}

func TestAllTemplatesLoad(t *testing.T) {
	for _, name := range Available() {
		t.Run(name, func(t *testing.T) {
			bundle, err := Load(name)
			if err != nil {
				t.Fatalf("Load(%q) failed: %v", name, err)
			}
			if bundle == nil {
				t.Fatalf("Load(%q) returned nil bundle", name)
			}
			if err := bundle.Validate(); err != nil {
				t.Fatalf("bundle validation failed: %v", err)
			}
		})
	}
}

func TestAllTemplatesHaveIdentities(t *testing.T) {
	for _, name := range Available() {
		t.Run(name, func(t *testing.T) {
			bundle, err := Load(name)
			if err != nil {
				t.Fatalf("Load(%q) failed: %v", name, err)
			}
			if len(bundle.Identities) < 3 {
				t.Fatalf("template %q has %d identities, want at least 3", name, len(bundle.Identities))
			}
		})
	}
}

func TestAllTemplatesHaveAttributes(t *testing.T) {
	for _, name := range Available() {
		t.Run(name, func(t *testing.T) {
			bundle, err := Load(name)
			if err != nil {
				t.Fatalf("Load(%q) failed: %v", name, err)
			}
			if len(bundle.Attributes) < 3 {
				t.Fatalf("template %q has %d attributes, want at least 3", name, len(bundle.Attributes))
			}
		})
	}
}

func TestAllTemplatesHaveAdmin(t *testing.T) {
	for _, name := range Available() {
		t.Run(name, func(t *testing.T) {
			bundle, err := Load(name)
			if err != nil {
				t.Fatalf("Load(%q) failed: %v", name, err)
			}
			hasAdmin := false
			for _, id := range bundle.Identities {
				if id.Admin {
					hasAdmin = true
					break
				}
			}
			if !hasAdmin {
				t.Fatalf("template %q has no admin identity", name)
			}
		})
	}
}

func TestAllTemplatesSealable(t *testing.T) {
	pubPath, privPath := writeSSHKeyPair(t)

	for _, name := range Available() {
		t.Run(name, func(t *testing.T) {
			bundle, err := Load(name)
			if err != nil {
				t.Fatalf("Load(%q) failed: %v", name, err)
			}

			// Seal with SSH key.
			if err := policybundle.SealWithSSHKey(bundle, pubPath); err != nil {
				t.Fatalf("SealWithSSHKey failed: %v", err)
			}

			// Sign with SSH key.
			if err := policybundle.SignBundle(bundle, privPath); err != nil {
				t.Fatalf("SignBundle failed: %v", err)
			}

			// Verify signature.
			if err := policybundle.VerifySignature(bundle, pubPath); err != nil {
				t.Fatalf("VerifySignature failed: %v", err)
			}

			// Unseal with SSH key.
			keys, err := policybundle.UnsealWithSSHKey(bundle, privPath)
			if err != nil {
				t.Fatalf("UnsealWithSSHKey failed: %v", err)
			}

			// Verify key material is present and valid.
			if keys.RSAPrivate == nil {
				t.Fatal("RSA private key is nil")
			}
			if err := keys.RSAPrivate.Validate(); err != nil {
				t.Fatalf("RSA key validation: %v", err)
			}
			if keys.ECPrivate == nil {
				t.Fatal("EC private key is nil")
			}
			if keys.IDPKey == nil {
				t.Fatal("IdP key is nil")
			}
			if err := keys.IDPKey.Validate(); err != nil {
				t.Fatalf("IdP key validation: %v", err)
			}
			if len(keys.RSACert) == 0 {
				t.Fatal("RSA cert is empty")
			}
			if len(keys.ECCert) == 0 {
				t.Fatal("EC cert is empty")
			}
		})
	}
}

func TestAvailableMatchesFiles(t *testing.T) {
	expected := []string{"healthcare", "finance", "defense"}
	got := Available()
	sort.Strings(expected)
	sort.Strings(got)
	if !reflect.DeepEqual(got, expected) {
		t.Fatalf("Available() = %v, want %v", got, expected)
	}
}

func TestLoadNonexistent(t *testing.T) {
	_, err := Load("nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent template, got nil")
	}
}

func TestDefenseTemplateRigor(t *testing.T) {
	bundle, err := Load("defense")
	if err != nil {
		t.Fatalf("Load(defense) failed: %v", err)
	}

	// 5 attributes.
	if len(bundle.Attributes) != 5 {
		t.Fatalf("defense has %d attributes, want 5", len(bundle.Attributes))
	}

	// Build attribute map for easy lookup.
	attrMap := make(map[string]policybundle.Attribute)
	for _, a := range bundle.Attributes {
		attrMap[a.Name] = a
	}

	// Verify required attribute names exist.
	requiredAttrs := []string{"classification", "sci_compartment", "sap_program", "releasability", "handling_caveat"}
	for _, name := range requiredAttrs {
		if _, ok := attrMap[name]; !ok {
			t.Fatalf("missing attribute %q", name)
		}
	}

	// Classification is hierarchy with correct order: TS > S > C > CUI > U.
	cls := attrMap["classification"]
	if cls.Rule != policybundle.RuleHierarchy {
		t.Fatalf("classification rule = %q, want hierarchy", cls.Rule)
	}
	expectedOrder := []string{"TOP_SECRET", "SECRET", "CONFIDENTIAL", "CUI", "UNCLASSIFIED"}
	if !reflect.DeepEqual(cls.Values, expectedOrder) {
		t.Fatalf("classification values = %v, want %v", cls.Values, expectedOrder)
	}

	// 7 identities.
	if len(bundle.Identities) != 7 {
		t.Fatalf("defense has %d identities, want 7", len(bundle.Identities))
	}

	// senior-analyst is admin.
	sa, ok := bundle.Identities["senior-analyst"]
	if !ok {
		t.Fatal("missing identity senior-analyst")
	}
	if !sa.Admin {
		t.Fatal("senior-analyst should be admin")
	}

	// senior-analyst has ALL values for ALL attributes.
	for _, attrName := range requiredAttrs {
		attr := attrMap[attrName]
		claim, hasClaim := sa.Claims[attrName]
		if !hasClaim {
			t.Fatalf("senior-analyst missing claim %q", attrName)
		}

		if attr.Rule == policybundle.RuleHierarchy {
			// Must have the highest value (first in list).
			s, ok := claim.(string)
			if !ok {
				t.Fatalf("senior-analyst claim %q is not a string", attrName)
			}
			if s != attr.Values[0] {
				t.Fatalf("senior-analyst %q = %q, want %q (highest)", attrName, s, attr.Values[0])
			}
		} else {
			// Must have all values.
			arr, ok := claim.([]string)
			if !ok {
				t.Fatalf("senior-analyst claim %q is not []string", attrName)
			}
			if len(arr) != len(attr.Values) {
				t.Fatalf("senior-analyst %q has %d values, want %d", attrName, len(arr), len(attr.Values))
			}
		}
	}

	// sigint-officer has only SI compartment.
	sigint, ok := bundle.Identities["sigint-officer"]
	if !ok {
		t.Fatal("missing identity sigint-officer")
	}
	sciClaim, hasSCI := sigint.Claims["sci_compartment"]
	if !hasSCI {
		t.Fatal("sigint-officer missing sci_compartment claim")
	}
	sciArr, ok := sciClaim.([]string)
	if !ok {
		t.Fatal("sigint-officer sci_compartment is not []string")
	}
	if len(sciArr) != 1 || sciArr[0] != "SI" {
		t.Fatalf("sigint-officer sci_compartment = %v, want [SI]", sciArr)
	}

	// allied-liaison has FVEY releasability but no SCI compartments.
	liaison, ok := bundle.Identities["allied-liaison"]
	if !ok {
		t.Fatal("missing identity allied-liaison")
	}
	relClaim, hasRel := liaison.Claims["releasability"]
	if !hasRel {
		t.Fatal("allied-liaison missing releasability claim")
	}
	relArr, ok := relClaim.([]string)
	if !ok {
		t.Fatal("allied-liaison releasability is not []string")
	}
	// Must contain FVEY.
	hasFVEY := false
	for _, v := range relArr {
		if v == "FVEY" {
			hasFVEY = true
			break
		}
	}
	if !hasFVEY {
		t.Fatalf("allied-liaison releasability %v does not contain FVEY", relArr)
	}
	// Must NOT have SCI compartments.
	if _, hasSCI := liaison.Claims["sci_compartment"]; hasSCI {
		t.Fatal("allied-liaison should not have sci_compartment")
	}
}

func TestHealthcareTemplateHIPAA(t *testing.T) {
	bundle, err := Load("healthcare")
	if err != nil {
		t.Fatalf("Load(healthcare) failed: %v", err)
	}

	// Find consent_purpose attribute.
	var found bool
	for _, attr := range bundle.Attributes {
		if attr.Name == "consent_purpose" {
			found = true
			if attr.Rule != policybundle.RuleAllOf {
				t.Fatalf("consent_purpose rule = %q, want allOf", attr.Rule)
			}
			break
		}
	}
	if !found {
		t.Fatal("healthcare template missing consent_purpose attribute")
	}
}

func TestFinanceTemplateSox(t *testing.T) {
	bundle, err := Load("finance")
	if err != nil {
		t.Fatalf("Load(finance) failed: %v", err)
	}

	// Find regulatory_scope attribute with sox value.
	var found bool
	for _, attr := range bundle.Attributes {
		if attr.Name == "regulatory_scope" {
			found = true
			hasSox := false
			for _, v := range attr.Values {
				if v == "sox" {
					hasSox = true
					break
				}
			}
			if !hasSox {
				t.Fatal("regulatory_scope does not contain sox")
			}
			break
		}
	}
	if !found {
		t.Fatal("finance template missing regulatory_scope attribute")
	}
}
