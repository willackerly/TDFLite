// Package idplite provides a lightweight built-in OIDC Identity Provider.
//
// It serves OIDC discovery, JWKS, and token endpoints backed by a JSON
// identity file. This replaces Keycloak for development and lightweight
// deployments. For production, swap in a real OIDC provider by using
// an external Authenticator implementation.
package idplite

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

const (
	defaultTokenTTL = 5 * time.Minute
	signingKeyID    = "idplite-signing-key"
	rsaKeyBits      = 2048
)

// Config holds configuration for the idplite server.
type Config struct {
	Issuer         string
	Audience       string        // audience claim in issued tokens (defaults to Issuer if empty)
	Port           int
	SigningKeyPath string        // path to RSA private key PEM (auto-generate if missing)
	IdentityFile   string        // path to identity.json
	TokenTTL       time.Duration // default 5 minutes
}

// Identity represents a user or client identity that can authenticate.
type Identity struct {
	ClientID     string         `json:"client_id"`
	ClientSecret string         `json:"client_secret"`
	Username     string         `json:"username,omitempty"`
	Password     string         `json:"password,omitempty"`
	SubjectID    string         `json:"subject_id"`
	Roles        []string       `json:"roles,omitempty"`
	CustomClaims map[string]any `json:"custom_claims,omitempty"`
}

// identityFile represents the on-disk JSON format for identities.
type identityFile struct {
	Users   []Identity `json:"users"`
	Clients []Identity `json:"clients"`
}

// Server is a lightweight OIDC Identity Provider that issues JWTs.
type Server struct {
	issuer     string
	audience   string // audience claim in issued tokens
	httpServer *http.Server
	signingKey jwk.Key // RSA private key for signing JWTs
	publicKeys jwk.Set // JWK Set for the /jwks endpoint
	identities []Identity
	tokenTTL   time.Duration

	mu       sync.Mutex
	ready    bool
	listener net.Listener
}

// New creates a new idplite Server with the given configuration.
func New(cfg Config) (*Server, error) {
	if cfg.Issuer == "" {
		return nil, fmt.Errorf("idplite: issuer URL is required")
	}
	if cfg.TokenTTL == 0 {
		cfg.TokenTTL = defaultTokenTTL
	}

	// Load or generate the signing key.
	privKey, err := loadOrGenerateKey(cfg.SigningKeyPath)
	if err != nil {
		return nil, fmt.Errorf("idplite: signing key: %w", err)
	}

	// Create JWK from the private key.
	sigKey, err := jwk.FromRaw(privKey)
	if err != nil {
		return nil, fmt.Errorf("idplite: create jwk from private key: %w", err)
	}
	if err := sigKey.Set(jwk.KeyIDKey, signingKeyID); err != nil {
		return nil, fmt.Errorf("idplite: set kid: %w", err)
	}
	if err := sigKey.Set(jwk.AlgorithmKey, jwa.RS256); err != nil {
		return nil, fmt.Errorf("idplite: set alg: %w", err)
	}
	if err := sigKey.Set(jwk.KeyUsageKey, "sig"); err != nil {
		return nil, fmt.Errorf("idplite: set use: %w", err)
	}

	// Create the public key set.
	pubKey, err := sigKey.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("idplite: extract public key: %w", err)
	}
	pubSet := jwk.NewSet()
	if err := pubSet.AddKey(pubKey); err != nil {
		return nil, fmt.Errorf("idplite: add public key to set: %w", err)
	}

	// Load identities.
	identities, err := loadIdentities(cfg.IdentityFile)
	if err != nil {
		return nil, fmt.Errorf("idplite: load identities: %w", err)
	}

	audience := cfg.Audience
	if audience == "" {
		audience = cfg.Issuer
	}

	s := &Server{
		issuer:     strings.TrimRight(cfg.Issuer, "/"),
		audience:   strings.TrimRight(audience, "/"),
		signingKey: sigKey,
		publicKeys: pubSet,
		identities: identities,
		tokenTTL:   cfg.TokenTTL,
	}

	// Build the HTTP mux.
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", s.handleDiscovery)
	mux.HandleFunc("GET /jwks", s.handleJWKS)
	mux.HandleFunc("POST /token", s.handleToken)
	// Handle CORS preflight for all endpoints.
	mux.HandleFunc("OPTIONS /", s.handleOptions)

	s.httpServer = &http.Server{
		Addr:    fmt.Sprintf(":%d", cfg.Port),
		Handler: corsMiddleware(mux),
	}

	return s, nil
}

// Start starts the HTTP server in a goroutine and returns once the server
// is ready to accept connections.
func (s *Server) Start(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.httpServer.Addr)
	if err != nil {
		return fmt.Errorf("idplite: listen: %w", err)
	}

	s.mu.Lock()
	s.listener = ln
	s.ready = true
	s.mu.Unlock()

	go func() {
		if err := s.httpServer.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Printf("idplite: server error: %v", err)
		}
		s.mu.Lock()
		s.ready = false
		s.mu.Unlock()
	}()

	return nil
}

// Stop gracefully shuts down the HTTP server.
func (s *Server) Stop(ctx context.Context) error {
	s.mu.Lock()
	s.ready = false
	s.mu.Unlock()
	return s.httpServer.Shutdown(ctx)
}

// Issuer returns the issuer URL.
func (s *Server) Issuer() string {
	return s.issuer
}

// Ready returns true if the server is listening for connections.
func (s *Server) Ready() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ready
}

// Addr returns the listener address, useful when started on port 0.
func (s *Server) Addr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener == nil {
		return ""
	}
	return s.listener.Addr().String()
}

// --- HTTP Handlers ---

func (s *Server) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	discovery := map[string]any{
		"issuer":                                s.issuer,
		"authorization_endpoint":                s.issuer + "/authorize",
		"token_endpoint":                        s.issuer + "/token",
		"jwks_uri":                              s.issuer + "/jwks",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"grant_types_supported":                 []string{"client_credentials", "password"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_post", "client_secret_basic"},
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(discovery); err != nil {
		log.Printf("idplite: discovery encode error: %v", err)
	}
}

func (s *Server) handleJWKS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	data, err := json.Marshal(s.publicKeys)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		log.Printf("idplite: jwks marshal error: %v", err)
		return
	}
	w.Write(data)
}

func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeTokenError(w, "invalid_request", "could not parse form", http.StatusBadRequest)
		return
	}

	grantType := r.FormValue("grant_type")
	switch grantType {
	case "client_credentials":
		s.handleClientCredentials(w, r)
	case "password":
		s.handlePasswordGrant(w, r)
	default:
		writeTokenError(w, "unsupported_grant_type",
			fmt.Sprintf("grant_type %q not supported", grantType), http.StatusBadRequest)
	}
}

func (s *Server) handleClientCredentials(w http.ResponseWriter, r *http.Request) {
	clientID, clientSecret, ok := extractClientCredentials(r)
	if !ok {
		writeTokenError(w, "invalid_client", "missing client credentials", http.StatusUnauthorized)
		return
	}

	identity, found := s.findByClientCredentials(clientID, clientSecret)
	if !found {
		writeTokenError(w, "invalid_client", "invalid client_id or client_secret", http.StatusUnauthorized)
		return
	}

	token, err := s.issueToken(identity, clientID, false)
	if err != nil {
		writeTokenError(w, "server_error", "failed to issue token", http.StatusInternalServerError)
		log.Printf("idplite: issue token error: %v", err)
		return
	}

	writeTokenResponse(w, token, int(s.tokenTTL.Seconds()))
}

func (s *Server) handlePasswordGrant(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")
	clientID := r.FormValue("client_id")

	if username == "" || password == "" {
		writeTokenError(w, "invalid_request", "username and password are required", http.StatusBadRequest)
		return
	}
	if clientID == "" {
		// Try to extract client_id from Basic auth if not in form.
		cid, _, ok := r.BasicAuth()
		if ok && cid != "" {
			clientID = cid
		} else {
			writeTokenError(w, "invalid_request", "client_id is required", http.StatusBadRequest)
			return
		}
	}

	identity, found := s.findByPassword(username, password)
	if !found {
		writeTokenError(w, "invalid_grant", "invalid username or password", http.StatusUnauthorized)
		return
	}

	token, err := s.issueToken(identity, clientID, true)
	if err != nil {
		writeTokenError(w, "server_error", "failed to issue token", http.StatusInternalServerError)
		log.Printf("idplite: issue token error: %v", err)
		return
	}

	writeTokenResponse(w, token, int(s.tokenTTL.Seconds()))
}

func (s *Server) handleOptions(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

// --- Token Issuance ---

func (s *Server) issueToken(identity Identity, clientID string, includeUsername bool) (string, error) {
	now := time.Now()

	builder := jwt.NewBuilder().
		Issuer(s.issuer).
		Subject(identity.SubjectID).
		Audience([]string{s.audience}).
		IssuedAt(now).
		Expiration(now.Add(s.tokenTTL)).
		JwtID(generateUUID()).
		Claim("client_id", clientID)

	if includeUsername && identity.Username != "" {
		builder = builder.Claim("preferred_username", identity.Username)
	}

	if len(identity.Roles) > 0 {
		builder = builder.Claim("realm_access", map[string]any{
			"roles": identity.Roles,
		})
	}

	// Emit custom claims as top-level JWT claims.
	for k, v := range identity.CustomClaims {
		builder = builder.Claim(k, v)
	}

	tok, err := builder.Build()
	if err != nil {
		return "", fmt.Errorf("build token: %w", err)
	}

	hdrs := jws.NewHeaders()
	if err := hdrs.Set(jws.KeyIDKey, signingKeyID); err != nil {
		return "", fmt.Errorf("set kid header: %w", err)
	}

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, s.signingKey, jws.WithProtectedHeaders(hdrs)))
	if err != nil {
		return "", fmt.Errorf("sign token: %w", err)
	}

	return string(signed), nil
}

// --- Identity Lookup ---

func (s *Server) findByClientCredentials(clientID, clientSecret string) (Identity, bool) {
	for _, id := range s.identities {
		if id.ClientID == clientID && id.ClientSecret == clientSecret {
			return id, true
		}
	}
	return Identity{}, false
}

func (s *Server) findByPassword(username, password string) (Identity, bool) {
	for _, id := range s.identities {
		if id.Username != "" && id.Username == username && id.Password == password {
			return id, true
		}
	}
	return Identity{}, false
}

// --- Key Management ---

func loadOrGenerateKey(path string) (*rsa.PrivateKey, error) {
	if path == "" {
		// No path specified; generate ephemeral key.
		return rsa.GenerateKey(rand.Reader, rsaKeyBits)
	}

	// Try to load existing key.
	data, err := os.ReadFile(path)
	if err == nil {
		return parsePrivateKeyPEM(data)
	}

	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read key file %s: %w", path, err)
	}

	// Generate and save a new key.
	privKey, err := rsa.GenerateKey(rand.Reader, rsaKeyBits)
	if err != nil {
		return nil, fmt.Errorf("generate RSA key: %w", err)
	}

	if err := savePrivateKeyPEM(path, privKey); err != nil {
		return nil, fmt.Errorf("save key to %s: %w", path, err)
	}

	return privKey, nil
}

func parsePrivateKeyPEM(data []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("PKCS8 key is not RSA")
		}
		return rsaKey, nil
	default:
		return nil, fmt.Errorf("unexpected PEM block type: %s", block.Type)
	}
}

func savePrivateKeyPEM(path string, key *rsa.PrivateKey) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create key directory: %w", err)
	}

	der := x509.MarshalPKCS1PrivateKey(key)
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: der,
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()

	return pem.Encode(f, block)
}

// --- Identity Loading ---

func loadIdentities(path string) ([]Identity, error) {
	if path == "" {
		return nil, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read identity file %s: %w", path, err)
	}

	var file identityFile
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("parse identity file: %w", err)
	}

	// Combine users and clients into a single identities list.
	// Users have both username/password and client_id/secret.
	// Clients have only client_id/secret.
	var identities []Identity
	identities = append(identities, file.Users...)
	identities = append(identities, file.Clients...)

	return identities, nil
}

// --- Response Helpers ---

func writeTokenResponse(w http.ResponseWriter, token string, expiresIn int) {
	resp := map[string]any{
		"access_token": token,
		"token_type":   "Bearer",
		"expires_in":   expiresIn,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func writeTokenError(w http.ResponseWriter, errorCode, description string, status int) {
	resp := map[string]string{
		"error":             errorCode,
		"error_description": description,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(resp)
}

// --- CORS Middleware ---

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		next.ServeHTTP(w, r)
	})
}

// --- Helpers ---

func extractClientCredentials(r *http.Request) (clientID, clientSecret string, ok bool) {
	// Try Basic auth first.
	if u, p, basicOK := r.BasicAuth(); basicOK && u != "" {
		return u, p, true
	}

	// Try form body.
	cid := r.FormValue("client_id")
	csec := r.FormValue("client_secret")
	if cid != "" && csec != "" {
		return cid, csec, true
	}

	return "", "", false
}

// generateUUID produces a v4 UUID string without external dependencies.
func generateUUID() string {
	var uuid [16]byte
	_, err := rand.Read(uuid[:])
	if err != nil {
		// Fallback to timestamp-based if crypto/rand fails (should never happen).
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	uuid[6] = (uuid[6] & 0x0f) | 0x40 // version 4
	uuid[8] = (uuid[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:16])
}
