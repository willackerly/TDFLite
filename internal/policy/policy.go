// Package policy defines the Policy service interface for TDFLite.
//
// The Policy service provides CRUD operations for namespaces, attribute
// definitions, attribute values, subject mappings, resource mappings,
// and key access registry. It delegates persistence to the store interface.
package policy

import (
	"net/http"
)

// Service is the policy administration service.
// It wires HTTP handlers to the store layer.
type Service interface {
	// RegisterRoutes adds policy CRUD endpoints to the HTTP mux.
	// Endpoints follow the OpenTDF API surface:
	//   /policy/namespaces/
	//   /policy/attributes/
	//   /policy/subject-mappings/
	//   /policy/resource-mappings/
	//   /policy/key-access-registry/
	RegisterRoutes(mux *http.ServeMux)
}
