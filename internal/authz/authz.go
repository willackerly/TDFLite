// Package authz defines the authorization interface for TDFLite.
//
// The default implementation is a Go-native ABAC engine that evaluates
// attribute rules (ALL_OF, ANY_OF, HIERARCHY). Swap in OPA/Rego, Casbin,
// or Cedar by implementing this interface.
package authz

import (
	"context"

	"github.com/willnorris/tdflite/internal/store"
)

// Decision represents an access control decision.
type Decision string

const (
	DecisionAllow Decision = "ALLOW"
	DecisionDeny  Decision = "DENY"
)

// EntityChain represents one or more entities in an authorization request.
// Entities are ordered from most to least specific (e.g., user, then org).
type EntityChain struct {
	Entities []Entity `json:"entities"`
}

// Entity represents a subject seeking access.
type Entity struct {
	ID         string         `json:"id"`
	EntityType string         `json:"entity_type"` // "user", "client", "service"
	Claims     map[string]any `json:"claims,omitempty"`
}

// Resource represents something being accessed.
type Resource struct {
	AttributeValues []*store.AttributeValue `json:"attribute_values"`
}

// Entitlement maps an entity to the attribute values it is entitled to.
type Entitlement struct {
	EntityID        string                  `json:"entity_id"`
	AttributeValues []*store.AttributeValue `json:"attribute_values"`
}

// DecisionRequest is a single access decision request.
type DecisionRequest struct {
	EntityChains []EntityChain    `json:"entity_chains"`
	Resource     Resource         `json:"resource"`
	Actions      []store.Action   `json:"actions"`
}

// DecisionResponse is the result of an access decision.
type DecisionResponse struct {
	Decision Decision `json:"decision"`
	Entity   Entity   `json:"entity"`
	Resource Resource `json:"resource"`
	Action   string   `json:"action"`
}

// Authorizer makes authorization decisions based on ABAC policies.
// Implementations must be safe for concurrent use.
type Authorizer interface {
	// GetEntitlements resolves the attribute values an entity is entitled to,
	// based on subject mappings and entity attributes.
	GetEntitlements(ctx context.Context, entities []Entity) ([]Entitlement, error)

	// GetDecisions evaluates access control for one or more entity chains
	// against resources and actions. Returns a decision per entity-resource-action triple.
	GetDecisions(ctx context.Context, requests []DecisionRequest) ([]DecisionResponse, error)
}
