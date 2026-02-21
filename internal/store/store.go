// Package store defines the persistence interface for TDFLite.
//
// All policy state, key material, and identity data flows through this interface.
// The default implementation is in-memory with optional JSON file persistence.
// Swap in PostgreSQL, SQLite, etcd, etc. by implementing this interface.
package store

import (
	"context"
	"time"
)

// Store is the top-level persistence interface. It provides access to
// domain-specific sub-stores. Implementations must be safe for concurrent use.
type Store interface {
	// PolicyStore returns the policy persistence layer.
	PolicyStore() PolicyStore
	// KeyStore returns the key material persistence layer.
	KeyStore() KeyStore
	// IdentityStore returns the identity/subject persistence layer.
	IdentityStore() IdentityStore
	// Close releases any resources held by the store.
	Close() error
}

// --- Policy Domain ---

// Namespace represents a top-level attribute namespace (e.g., "https://example.com/attr").
type Namespace struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Active    bool      `json:"active"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// AttributeDefinition defines an attribute with a rule type.
type AttributeDefinition struct {
	ID          string           `json:"id"`
	NamespaceID string           `json:"namespace_id"`
	Name        string           `json:"name"`
	Rule        AttributeRule    `json:"rule"`
	Values      []AttributeValue `json:"values,omitempty"`
	Active      bool             `json:"active"`
	CreatedAt   time.Time        `json:"created_at"`
	UpdatedAt   time.Time        `json:"updated_at"`
}

// AttributeRule defines how attribute values are evaluated for access.
type AttributeRule string

const (
	RuleAllOf     AttributeRule = "ALL_OF"
	RuleAnyOf     AttributeRule = "ANY_OF"
	RuleHierarchy AttributeRule = "HIERARCHY"
)

// AttributeValue is a single value within an attribute definition.
type AttributeValue struct {
	ID                    string    `json:"id"`
	AttributeDefinitionID string    `json:"attribute_definition_id"`
	Value                 string    `json:"value"`
	Active                bool      `json:"active"`
	CreatedAt             time.Time `json:"created_at"`
	UpdatedAt             time.Time `json:"updated_at"`
}

// SubjectMapping maps a subject condition set to attribute values with actions.
type SubjectMapping struct {
	ID                    string              `json:"id"`
	AttributeValueID      string              `json:"attribute_value_id"`
	SubjectConditionSetID string              `json:"subject_condition_set_id"`
	Actions               []Action            `json:"actions"`
	ConditionSet          *SubjectConditionSet `json:"condition_set,omitempty"`
	CreatedAt             time.Time           `json:"created_at"`
	UpdatedAt             time.Time           `json:"updated_at"`
}

// Action represents a permitted action (e.g., DECRYPT, TRANSMIT).
type Action struct {
	Name string `json:"name"`
}

// SubjectConditionSet defines conditions that match entity tokens/claims.
type SubjectConditionSet struct {
	ID         string           `json:"id"`
	Conditions []ConditionGroup `json:"conditions"`
	CreatedAt  time.Time        `json:"created_at"`
	UpdatedAt  time.Time        `json:"updated_at"`
}

// ConditionGroup is a set of conditions joined by a boolean operator.
type ConditionGroup struct {
	Operator   BooleanOperator `json:"operator"`
	Conditions []Condition     `json:"conditions"`
}

// BooleanOperator for condition groups.
type BooleanOperator string

const (
	BoolAnd BooleanOperator = "AND"
	BoolOr  BooleanOperator = "OR"
)

// Condition is a single condition that evaluates a subject property.
type Condition struct {
	SubjectExternalSelectorValue string   `json:"subject_external_selector_value"`
	Operator                     string   `json:"operator"`
	SubjectExternalValues        []string `json:"subject_external_values"`
}

// ResourceMapping maps a resource term to attribute values.
type ResourceMapping struct {
	ID               string    `json:"id"`
	AttributeValueID string    `json:"attribute_value_id"`
	Terms            []string  `json:"terms"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

// PolicyStore handles CRUD for policy objects.
type PolicyStore interface {
	// Namespaces
	CreateNamespace(ctx context.Context, ns *Namespace) error
	GetNamespace(ctx context.Context, id string) (*Namespace, error)
	ListNamespaces(ctx context.Context) ([]*Namespace, error)
	UpdateNamespace(ctx context.Context, ns *Namespace) error
	DeactivateNamespace(ctx context.Context, id string) error

	// Attribute Definitions
	CreateAttributeDefinition(ctx context.Context, def *AttributeDefinition) error
	GetAttributeDefinition(ctx context.Context, id string) (*AttributeDefinition, error)
	ListAttributeDefinitions(ctx context.Context, namespaceID string) ([]*AttributeDefinition, error)
	UpdateAttributeDefinition(ctx context.Context, def *AttributeDefinition) error
	DeactivateAttributeDefinition(ctx context.Context, id string) error

	// Attribute Values
	CreateAttributeValue(ctx context.Context, val *AttributeValue) error
	GetAttributeValue(ctx context.Context, id string) (*AttributeValue, error)
	ListAttributeValues(ctx context.Context, definitionID string) ([]*AttributeValue, error)
	UpdateAttributeValue(ctx context.Context, val *AttributeValue) error
	DeactivateAttributeValue(ctx context.Context, id string) error

	// Subject Mappings
	CreateSubjectMapping(ctx context.Context, sm *SubjectMapping) error
	GetSubjectMapping(ctx context.Context, id string) (*SubjectMapping, error)
	ListSubjectMappings(ctx context.Context) ([]*SubjectMapping, error)
	UpdateSubjectMapping(ctx context.Context, sm *SubjectMapping) error
	DeleteSubjectMapping(ctx context.Context, id string) error

	// Subject Condition Sets
	CreateSubjectConditionSet(ctx context.Context, scs *SubjectConditionSet) error
	GetSubjectConditionSet(ctx context.Context, id string) (*SubjectConditionSet, error)
	ListSubjectConditionSets(ctx context.Context) ([]*SubjectConditionSet, error)
	UpdateSubjectConditionSet(ctx context.Context, scs *SubjectConditionSet) error
	DeleteSubjectConditionSet(ctx context.Context, id string) error

	// Resource Mappings
	CreateResourceMapping(ctx context.Context, rm *ResourceMapping) error
	GetResourceMapping(ctx context.Context, id string) (*ResourceMapping, error)
	ListResourceMappings(ctx context.Context) ([]*ResourceMapping, error)
	UpdateResourceMapping(ctx context.Context, rm *ResourceMapping) error
	DeleteResourceMapping(ctx context.Context, id string) error
}

// --- Key Domain ---

// RegisteredKey represents a cryptographic key pair managed by the platform.
type RegisteredKey struct {
	ID               string    `json:"id"`
	Algorithm        string    `json:"algorithm"` // "rsa:2048", "ec:secp256r1"
	PublicKey        string    `json:"public_key"` // PEM-encoded
	WrappedPrivateKey string   `json:"wrapped_private_key,omitempty"` // encrypted PEM
	KASServerID      string    `json:"kas_server_id"`
	Active           bool      `json:"active"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

// KASRegistration represents a registered Key Access Server.
type KASRegistration struct {
	ID        string    `json:"id"`
	URI       string    `json:"uri"`
	Name      string    `json:"name"`
	Active    bool      `json:"active"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// KeyAccessGrant links a key to an attribute value, definition, or namespace.
type KeyAccessGrant struct {
	ID               string `json:"id"`
	KeyID            string `json:"key_id"`
	AttributeValueID string `json:"attribute_value_id,omitempty"`
	DefinitionID     string `json:"definition_id,omitempty"`
	NamespaceID      string `json:"namespace_id,omitempty"`
}

// KeyStore handles persistence for cryptographic keys and KAS registrations.
type KeyStore interface {
	// KAS Registrations
	CreateKASRegistration(ctx context.Context, kas *KASRegistration) error
	GetKASRegistration(ctx context.Context, id string) (*KASRegistration, error)
	ListKASRegistrations(ctx context.Context) ([]*KASRegistration, error)
	UpdateKASRegistration(ctx context.Context, kas *KASRegistration) error
	DeleteKASRegistration(ctx context.Context, id string) error

	// Registered Keys
	CreateKey(ctx context.Context, key *RegisteredKey) error
	GetKey(ctx context.Context, id string) (*RegisteredKey, error)
	ListKeys(ctx context.Context, kasID string) ([]*RegisteredKey, error)
	UpdateKey(ctx context.Context, key *RegisteredKey) error
	DeleteKey(ctx context.Context, id string) error

	// Key Access Grants
	CreateKeyAccessGrant(ctx context.Context, grant *KeyAccessGrant) error
	ListKeyAccessGrants(ctx context.Context, keyID string) ([]*KeyAccessGrant, error)
	DeleteKeyAccessGrant(ctx context.Context, id string) error
}

// --- Identity Domain ---

// Identity represents a user or service account in the lightweight IdP.
type Identity struct {
	ID           string            `json:"id"`
	Subject      string            `json:"subject"`
	Email        string            `json:"email,omitempty"`
	Name         string            `json:"name,omitempty"`
	PasswordHash string            `json:"password_hash,omitempty"`
	ClientID     string            `json:"client_id,omitempty"`
	ClientSecret string            `json:"client_secret,omitempty"`
	Claims       map[string]any    `json:"claims,omitempty"`
	Active       bool              `json:"active"`
	CreatedAt    time.Time         `json:"created_at"`
	UpdatedAt    time.Time         `json:"updated_at"`
}

// IdentityStore handles persistence for identity/subject data.
type IdentityStore interface {
	CreateIdentity(ctx context.Context, id *Identity) error
	GetIdentity(ctx context.Context, id string) (*Identity, error)
	GetIdentityBySubject(ctx context.Context, subject string) (*Identity, error)
	GetIdentityByClientID(ctx context.Context, clientID string) (*Identity, error)
	ListIdentities(ctx context.Context) ([]*Identity, error)
	UpdateIdentity(ctx context.Context, id *Identity) error
	DeleteIdentity(ctx context.Context, id string) error
}
