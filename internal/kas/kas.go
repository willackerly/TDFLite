// Package kas defines the Key Access Server interface for TDFLite.
//
// KAS manages cryptographic key lifecycle and enforces access control
// by granting or withholding encryption keys for TDF decryption.
// The default implementation uses software-based crypto.
// Swap in HSM, AWS KMS, or Vault Transit by implementing CryptoProvider.
package kas

import (
	"context"
	"net/http"
)

// PublicKeyRequest is the request to get a KAS public key.
type PublicKeyRequest struct {
	Algorithm string `json:"algorithm"` // "rsa:2048", "ec:secp256r1"
	Format    string `json:"fmt"`       // "pem", "jwk"
}

// PublicKeyResponse is the KAS public key response.
type PublicKeyResponse struct {
	PublicKey string `json:"public_key"`
	KID       string `json:"kid"` // Key ID
}

// RewrapRequest is the request to unwrap and re-wrap a DEK.
type RewrapRequest struct {
	SignedRequestToken string `json:"signedRequestToken"` // JWT containing the rewrap body
}

// RewrapResponse is the rewrapped key response.
type RewrapResponse struct {
	EntityWrappedKey string `json:"entityWrappedKey"` // DEK re-encrypted with entity's public key
	SessionPublicKey string `json:"sessionPublicKey"` // Session ephemeral public key
	SchemaVersion    string `json:"schemaVersion"`
}

// KeyAccessServer provides key management and access control enforcement.
// Implementations must be safe for concurrent use.
type KeyAccessServer interface {
	// PublicKey returns the KAS public key for the given algorithm.
	PublicKey(ctx context.Context, req *PublicKeyRequest) (*PublicKeyResponse, error)

	// Rewrap unwraps a DEK, checks authorization, and re-wraps with the entity's key.
	Rewrap(ctx context.Context, req *RewrapRequest) (*RewrapResponse, error)

	// RegisterRoutes adds KAS endpoints to the HTTP mux:
	//   GET  /kas/v2/kas_public_key
	//   POST /kas/v2/rewrap
	RegisterRoutes(mux *http.ServeMux)
}
