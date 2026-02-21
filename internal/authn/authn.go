// Package authn defines the authentication interface for TDFLite.
//
// The default implementation is a lightweight built-in OIDC IdP that issues
// JWTs and serves OIDC discovery + JWKS endpoints. Swap in Keycloak, Auth0,
// or any OIDC-compliant provider by implementing this interface.
package authn

import (
	"context"
	"net/http"
)

// TokenClaims represents validated claims extracted from a bearer token.
type TokenClaims struct {
	Subject  string         `json:"sub"`
	Issuer   string         `json:"iss"`
	Audience []string       `json:"aud"`
	Email    string         `json:"email,omitempty"`
	Name     string         `json:"name,omitempty"`
	ClientID string         `json:"client_id,omitempty"`
	Expiry   int64          `json:"exp"`
	IssuedAt int64          `json:"iat"`
	Extra    map[string]any `json:"extra,omitempty"`
}

// Authenticator validates bearer tokens and extracts claims.
// Implementations must be safe for concurrent use.
type Authenticator interface {
	// ValidateToken validates a bearer token and returns the claims.
	// Returns an error if the token is invalid, expired, or untrusted.
	ValidateToken(ctx context.Context, token string) (*TokenClaims, error)

	// Issuer returns the OIDC issuer URL for this authenticator.
	Issuer() string
}

// TokenIssuer issues tokens. Only needed for the built-in IdP;
// external providers handle this themselves.
type TokenIssuer interface {
	// IssueToken creates a signed JWT for the given subject and claims.
	IssueToken(ctx context.Context, subject string, claims map[string]any) (string, error)

	// IssueClientCredentialsToken creates a token for a client_credentials grant.
	IssueClientCredentialsToken(ctx context.Context, clientID, clientSecret string) (string, error)
}

// OIDCProvider serves the OIDC discovery and JWKS endpoints.
// Only needed for the built-in IdP.
type OIDCProvider interface {
	Authenticator
	TokenIssuer

	// RegisterRoutes adds OIDC endpoints to the HTTP mux:
	//   GET /.well-known/openid-configuration
	//   GET /jwks
	//   POST /token
	RegisterRoutes(mux *http.ServeMux)
}

// Middleware returns an HTTP middleware that validates bearer tokens
// and injects TokenClaims into the request context.
func Middleware(auth Authenticator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Extract bearer token from Authorization header.
			authHeader := r.Header.Get("Authorization")
			if len(authHeader) < 7 || authHeader[:7] != "Bearer " {
				http.Error(w, "missing or invalid authorization header", http.StatusUnauthorized)
				return
			}
			token := authHeader[7:]

			claims, err := auth.ValidateToken(r.Context(), token)
			if err != nil {
				http.Error(w, "invalid token: "+err.Error(), http.StatusUnauthorized)
				return
			}

			ctx := ContextWithClaims(r.Context(), claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

type contextKey string

const claimsKey contextKey = "authn_claims"

// ContextWithClaims stores claims in a context.
func ContextWithClaims(ctx context.Context, claims *TokenClaims) context.Context {
	return context.WithValue(ctx, claimsKey, claims)
}

// ClaimsFromContext retrieves claims from a context.
func ClaimsFromContext(ctx context.Context) (*TokenClaims, bool) {
	claims, ok := ctx.Value(claimsKey).(*TokenClaims)
	return claims, ok
}
