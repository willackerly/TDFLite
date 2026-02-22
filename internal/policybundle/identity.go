package policybundle

import (
	"fmt"
	"sort"

	"github.com/willackerly/TDFLite/internal/idplite"
)

// builtInOpentdf is the admin service account used by the platform itself.
var builtInOpentdf = idplite.Identity{
	ClientID:     "opentdf",
	ClientSecret: "secret",
	SubjectID:    "00000000-0000-0000-0000-000000000003",
	Roles:        []string{"opentdf-admin", "opentdf-standard"},
}

// builtInSDK is the standard SDK service account.
var builtInSDK = idplite.Identity{
	ClientID:     "opentdf-sdk",
	ClientSecret: "secret",
	SubjectID:    "00000000-0000-0000-0000-000000000002",
	Roles:        []string{"opentdf-standard"},
}

// IdentityOutput holds generated identities split into users and clients,
// matching the JSON structure idplite expects from its identity file.
type IdentityOutput struct {
	Users   []idplite.Identity `json:"users"`
	Clients []idplite.Identity `json:"clients"`
}

// All returns all identities (users + clients) as a flat slice.
func (o *IdentityOutput) All() []idplite.Identity {
	result := make([]idplite.Identity, 0, len(o.Users)+len(o.Clients))
	result = append(result, o.Users...)
	result = append(result, o.Clients...)
	return result
}

// GenerateIdentities converts a policy bundle's identity definitions into the
// idplite identity format. Each bundle identity becomes a user entry with both
// username/password and client_id/client_secret credentials. The two built-in
// service accounts (opentdf and opentdf-sdk) are always appended as clients.
//
// Subject IDs are deterministically assigned starting at index 10 for user
// identities (sorted by name for stability).
func GenerateIdentities(bundle *Bundle) (*IdentityOutput, error) {
	if bundle == nil {
		return nil, fmt.Errorf("generate identities: bundle is nil")
	}

	// Sort identity names for deterministic subject ID assignment and output order.
	names := make([]string, 0, len(bundle.Identities))
	for name := range bundle.Identities {
		names = append(names, name)
	}
	sort.Strings(names)

	users := make([]idplite.Identity, 0, len(names))
	for i, name := range names {
		bundleID := bundle.Identities[name]

		// Determine role based on admin flag.
		var roles []string
		if bundleID.Admin {
			roles = []string{"opentdf-admin", "opentdf-standard"}
		} else {
			roles = []string{"opentdf-standard"}
		}

		// Build custom claims from the identity's Claims field.
		// These become top-level JWT claims for subject mapping selectors.
		var customClaims map[string]any
		if len(bundleID.Claims) > 0 {
			customClaims = make(map[string]any, len(bundleID.Claims))
			for k, v := range bundleID.Claims {
				customClaims[k] = v
			}
		}

		user := idplite.Identity{
			ClientID:     bundleID.EffectiveClientID(name),
			ClientSecret: bundleID.EffectiveClientSecret(name),
			Username:     name,
			Password:     bundleID.EffectivePassword(name),
			SubjectID:    fmt.Sprintf("00000000-0000-0000-0000-%012d", 10+i),
			Roles:        roles,
			CustomClaims: customClaims,
		}

		users = append(users, user)
	}

	// Always include the two built-in service accounts as clients.
	clients := []idplite.Identity{builtInSDK, builtInOpentdf}

	return &IdentityOutput{
		Users:   users,
		Clients: clients,
	}, nil
}
