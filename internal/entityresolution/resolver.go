// Package entityresolution defines the entity resolution interface for TDFLite.
//
// Entity resolution takes an entity identifier (JWT claims, email, client_id)
// and resolves it to a set of attributes needed for authorization decisions.
// The default implementation extracts attributes from JWT claims.
// Swap in LDAP, SCIM, or a database lookup by implementing this interface.
package entityresolution

import (
	"context"

	"github.com/willnorris/tdflite/internal/authz"
)

// EntityIdentifier specifies how to identify an entity for resolution.
type EntityIdentifier struct {
	// Type is the identifier type: "email", "username", "client_id", "claims", "uuid".
	Type string `json:"type"`
	// Value is the identifier value.
	Value string `json:"value"`
	// Claims are the raw JWT claims (when Type is "claims").
	Claims map[string]any `json:"claims,omitempty"`
}

// ResolvedEntity is an entity with its resolved attributes.
type ResolvedEntity struct {
	Entity     authz.Entity   `json:"entity"`
	Attributes map[string]any `json:"attributes"`
}

// Resolver resolves entity identifiers to attribute sets.
// Implementations must be safe for concurrent use.
type Resolver interface {
	// Resolve takes entity identifiers and returns resolved entities with attributes.
	Resolve(ctx context.Context, identifiers []EntityIdentifier) ([]ResolvedEntity, error)
}
