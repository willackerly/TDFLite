// Package idplite provides a lightweight built-in OIDC Identity Provider.
//
// It serves OIDC discovery, JWKS, and token endpoints backed by a JSON
// identity file. This replaces Keycloak for development and lightweight
// deployments. For production, swap in a real OIDC provider by using
// an external Authenticator implementation.
package idplite

// Placeholder for the lightweight OIDC IdP implementation.
// Will implement authn.OIDCProvider interface with:
//
// - OIDC Discovery: GET /.well-known/openid-configuration
// - JWKS: GET /jwks
// - Token: POST /token (client_credentials and password grants)
// - Token validation using local JWKS
// - RSA or EC signing keys (auto-generated or loaded from config)
// - Identity state loaded from JSON file via store.IdentityStore
