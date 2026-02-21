// Package engine provides a Go-native ABAC authorization engine.
//
// It evaluates attribute rules (ALL_OF, ANY_OF, HIERARCHY) without
// requiring external policy engines like OPA or Casbin.
// For more complex policy needs, swap in OPA/Rego or Casbin
// by implementing the authz.Authorizer interface.
package engine

// Placeholder for the ABAC engine implementation.
// Will implement authz.Authorizer interface with:
//
// - GetEntitlements: resolve subject mappings → entity attribute values
// - GetDecisions: evaluate attribute rules against entity entitlements
//
// Rule evaluation:
// - ALL_OF: entity must have ALL attribute values assigned to the resource
// - ANY_OF: entity must have at least ONE attribute value
// - HIERARCHY: entity must have a value at or above the resource's value
//   in the defined value order
