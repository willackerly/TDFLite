package idplite

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// testServer creates an idplite server for testing with a temporary identity file.
func testServer(t *testing.T) (*Server, string) {
	t.Helper()

	tmpDir := t.TempDir()

	// Write test identity file.
	identityData := `{
		"users": [
			{
				"username": "admin",
				"password": "changeme",
				"client_id": "admin-client",
				"client_secret": "admin-secret",
				"subject_id": "00000000-0000-0000-0000-000000000001",
				"roles": ["admin", "standard"]
			}
		],
		"clients": [
			{
				"client_id": "opentdf-sdk",
				"client_secret": "secret",
				"subject_id": "00000000-0000-0000-0000-000000000002",
				"roles": ["standard"]
			},
			{
				"client_id": "opentdf",
				"client_secret": "secret",
				"subject_id": "00000000-0000-0000-0000-000000000003",
				"roles": ["admin", "standard"]
			}
		]
	}`

	identityPath := filepath.Join(tmpDir, "identity.json")
	if err := os.WriteFile(identityPath, []byte(identityData), 0o644); err != nil {
		t.Fatalf("write identity file: %v", err)
	}

	keyPath := filepath.Join(tmpDir, "signing-key.pem")

	srv, err := New(Config{
		Issuer:         "http://localhost:0",
		Port:           0,
		SigningKeyPath: keyPath,
		IdentityFile:   identityPath,
		TokenTTL:       5 * time.Minute,
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	ctx := context.Background()
	if err := srv.Start(ctx); err != nil {
		t.Fatalf("Start() error: %v", err)
	}

	// Update issuer to reflect actual address.
	addr := srv.Addr()
	baseURL := fmt.Sprintf("http://%s", addr)
	srv.issuer = baseURL

	t.Cleanup(func() {
		srv.Stop(context.Background())
	})

	return srv, baseURL
}

func TestDiscoveryEndpoint(t *testing.T) {
	_, baseURL := testServer(t)

	resp, err := http.Get(baseURL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("GET discovery: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Fatalf("expected Content-Type application/json, got %s", ct)
	}

	var discovery map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&discovery); err != nil {
		t.Fatalf("decode discovery: %v", err)
	}

	// Verify issuer matches.
	issuer, ok := discovery["issuer"].(string)
	if !ok || issuer != baseURL {
		t.Errorf("expected issuer %q, got %q", baseURL, issuer)
	}

	// Verify required fields exist.
	requiredFields := []string{
		"token_endpoint", "jwks_uri",
		"grant_types_supported", "response_types_supported",
		"subject_types_supported", "id_token_signing_alg_values_supported",
		"token_endpoint_auth_methods_supported",
	}
	for _, field := range requiredFields {
		if _, exists := discovery[field]; !exists {
			t.Errorf("missing required field: %s", field)
		}
	}

	// Verify token_endpoint uses correct base URL.
	tokenEndpoint, _ := discovery["token_endpoint"].(string)
	if !strings.HasPrefix(tokenEndpoint, baseURL) {
		t.Errorf("token_endpoint %q should start with %q", tokenEndpoint, baseURL)
	}
}

func TestJWKSEndpoint(t *testing.T) {
	_, baseURL := testServer(t)

	resp, err := http.Get(baseURL + "/jwks")
	if err != nil {
		t.Fatalf("GET /jwks: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	set, err := jwk.Parse(body)
	if err != nil {
		t.Fatalf("parse JWK Set: %v", err)
	}

	if set.Len() == 0 {
		t.Fatal("JWK Set contains no keys")
	}

	// Verify the key has the expected attributes.
	key, ok := set.Key(0)
	if !ok {
		t.Fatal("could not get key at index 0")
	}

	kid := key.KeyID()
	if kid != signingKeyID {
		t.Errorf("expected kid %q, got %q", signingKeyID, kid)
	}

	alg := key.Algorithm()
	if alg.String() != jwa.RS256.String() {
		t.Errorf("expected alg RS256, got %v", alg)
	}
}

func TestClientCredentialsGrant(t *testing.T) {
	_, baseURL := testServer(t)

	// Test with form body credentials.
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"opentdf-sdk"},
		"client_secret": {"secret"},
	}

	resp, err := http.PostForm(baseURL+"/token", form)
	if err != nil {
		t.Fatalf("POST /token: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
	}

	var tokenResp map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		t.Fatalf("decode token response: %v", err)
	}

	accessToken, ok := tokenResp["access_token"].(string)
	if !ok || accessToken == "" {
		t.Fatal("missing or empty access_token")
	}

	tokenType, ok := tokenResp["token_type"].(string)
	if !ok || tokenType != "Bearer" {
		t.Errorf("expected token_type Bearer, got %q", tokenType)
	}

	expiresIn, ok := tokenResp["expires_in"].(float64)
	if !ok || expiresIn <= 0 {
		t.Errorf("expected positive expires_in, got %v", expiresIn)
	}
}

func TestClientCredentialsGrantBasicAuth(t *testing.T) {
	_, baseURL := testServer(t)

	form := url.Values{
		"grant_type": {"client_credentials"},
	}

	req, err := http.NewRequest("POST", baseURL+"/token",
		strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("opentdf-sdk", "secret")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /token: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
	}
}

func TestClientCredentialsInvalidCredentials(t *testing.T) {
	_, baseURL := testServer(t)

	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"opentdf-sdk"},
		"client_secret": {"wrong-secret"},
	}

	resp, err := http.PostForm(baseURL+"/token", form)
	if err != nil {
		t.Fatalf("POST /token: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}

	var errResp map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&errResp); err != nil {
		t.Fatalf("decode error response: %v", err)
	}

	if errResp["error"] != "invalid_client" {
		t.Errorf("expected error 'invalid_client', got %q", errResp["error"])
	}
}

func TestPasswordGrant(t *testing.T) {
	_, baseURL := testServer(t)

	form := url.Values{
		"grant_type": {"password"},
		"username":   {"admin"},
		"password":   {"changeme"},
		"client_id":  {"admin-client"},
	}

	resp, err := http.PostForm(baseURL+"/token", form)
	if err != nil {
		t.Fatalf("POST /token: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
	}

	var tokenResp map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		t.Fatalf("decode token response: %v", err)
	}

	accessToken, ok := tokenResp["access_token"].(string)
	if !ok || accessToken == "" {
		t.Fatal("missing or empty access_token")
	}

	// Parse the token and verify preferred_username claim.
	tok, err := jwt.Parse([]byte(accessToken), jwt.WithVerify(false))
	if err != nil {
		t.Fatalf("parse token: %v", err)
	}

	username, ok := tok.PrivateClaims()["preferred_username"].(string)
	if !ok || username != "admin" {
		t.Errorf("expected preferred_username 'admin', got %q", username)
	}
}

func TestPasswordGrantInvalidCredentials(t *testing.T) {
	_, baseURL := testServer(t)

	form := url.Values{
		"grant_type": {"password"},
		"username":   {"admin"},
		"password":   {"wrongpassword"},
		"client_id":  {"admin-client"},
	}

	resp, err := http.PostForm(baseURL+"/token", form)
	if err != nil {
		t.Fatalf("POST /token: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

func TestTokenClaims(t *testing.T) {
	_, baseURL := testServer(t)

	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"opentdf"},
		"client_secret": {"secret"},
	}

	resp, err := http.PostForm(baseURL+"/token", form)
	if err != nil {
		t.Fatalf("POST /token: %v", err)
	}
	defer resp.Body.Close()

	var tokenResp map[string]any
	json.NewDecoder(resp.Body).Decode(&tokenResp)

	accessToken := tokenResp["access_token"].(string)

	tok, err := jwt.Parse([]byte(accessToken), jwt.WithVerify(false))
	if err != nil {
		t.Fatalf("parse token: %v", err)
	}

	// Verify standard claims.
	if tok.Issuer() != baseURL {
		t.Errorf("expected issuer %q, got %q", baseURL, tok.Issuer())
	}
	if tok.Subject() != "00000000-0000-0000-0000-000000000003" {
		t.Errorf("expected subject '00000000-0000-0000-0000-000000000003', got %q", tok.Subject())
	}

	aud := tok.Audience()
	if len(aud) == 0 {
		t.Error("expected non-empty audience")
	}

	if tok.Expiration().IsZero() {
		t.Error("expected non-zero expiration")
	}
	if tok.IssuedAt().IsZero() {
		t.Error("expected non-zero issued at")
	}

	// Verify custom claims.
	clientID, ok := tok.PrivateClaims()["client_id"].(string)
	if !ok || clientID != "opentdf" {
		t.Errorf("expected client_id 'opentdf', got %q", clientID)
	}

	jti := tok.JwtID()
	if jti == "" {
		t.Error("expected non-empty jti")
	}

	// Verify realm_access.roles.
	realmAccess, ok := tok.PrivateClaims()["realm_access"].(map[string]any)
	if !ok {
		t.Fatal("expected realm_access claim")
	}
	roles, ok := realmAccess["roles"].([]any)
	if !ok || len(roles) == 0 {
		t.Fatal("expected non-empty roles in realm_access")
	}

	// opentdf has admin and standard roles.
	foundAdmin := false
	foundStandard := false
	for _, r := range roles {
		switch r.(string) {
		case "admin":
			foundAdmin = true
		case "standard":
			foundStandard = true
		}
	}
	if !foundAdmin || !foundStandard {
		t.Errorf("expected admin and standard roles, got %v", roles)
	}
}

func TestTokenVerifiableAgainstJWKS(t *testing.T) {
	_, baseURL := testServer(t)

	// Get JWKS.
	jwksResp, err := http.Get(baseURL + "/jwks")
	if err != nil {
		t.Fatalf("GET /jwks: %v", err)
	}
	defer jwksResp.Body.Close()

	jwksBody, err := io.ReadAll(jwksResp.Body)
	if err != nil {
		t.Fatalf("read jwks body: %v", err)
	}

	keySet, err := jwk.Parse(jwksBody)
	if err != nil {
		t.Fatalf("parse jwks: %v", err)
	}

	// Get a token.
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"opentdf-sdk"},
		"client_secret": {"secret"},
	}

	tokenResp, err := http.PostForm(baseURL+"/token", form)
	if err != nil {
		t.Fatalf("POST /token: %v", err)
	}
	defer tokenResp.Body.Close()

	var tr map[string]any
	json.NewDecoder(tokenResp.Body).Decode(&tr)
	accessToken := tr["access_token"].(string)

	// Verify the token against the JWKS.
	_, err = jwt.Parse([]byte(accessToken), jwt.WithKeySet(keySet))
	if err != nil {
		t.Fatalf("token verification against JWKS failed: %v", err)
	}
}

func TestUnsupportedGrantType(t *testing.T) {
	_, baseURL := testServer(t)

	form := url.Values{
		"grant_type": {"authorization_code"},
	}

	resp, err := http.PostForm(baseURL+"/token", form)
	if err != nil {
		t.Fatalf("POST /token: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestServerReadyAndAddr(t *testing.T) {
	srv, _ := testServer(t)

	if !srv.Ready() {
		t.Error("expected server to be ready")
	}

	addr := srv.Addr()
	if addr == "" {
		t.Error("expected non-empty address")
	}

	issuer := srv.Issuer()
	if issuer == "" {
		t.Error("expected non-empty issuer")
	}
}

func TestCORSHeaders(t *testing.T) {
	_, baseURL := testServer(t)

	resp, err := http.Get(baseURL + "/jwks")
	if err != nil {
		t.Fatalf("GET /jwks: %v", err)
	}
	defer resp.Body.Close()

	origin := resp.Header.Get("Access-Control-Allow-Origin")
	if origin != "*" {
		t.Errorf("expected Access-Control-Allow-Origin *, got %q", origin)
	}
}

func TestKeyPersistence(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "keys", "signing-key.pem")

	// First generation should create the key file.
	key1, err := loadOrGenerateKey(keyPath)
	if err != nil {
		t.Fatalf("first loadOrGenerateKey: %v", err)
	}

	// Verify file exists.
	if _, err := os.Stat(keyPath); err != nil {
		t.Fatalf("key file should exist: %v", err)
	}

	// Second load should return the same key.
	key2, err := loadOrGenerateKey(keyPath)
	if err != nil {
		t.Fatalf("second loadOrGenerateKey: %v", err)
	}

	if key1.N.Cmp(key2.N) != 0 {
		t.Error("loaded key should match generated key")
	}
}

func TestClientCannotUsePasswordGrant(t *testing.T) {
	_, baseURL := testServer(t)

	// Clients (opentdf-sdk) don't have username/password,
	// so password grant should fail for them.
	form := url.Values{
		"grant_type": {"password"},
		"username":   {"opentdf-sdk"},
		"password":   {"secret"},
		"client_id":  {"opentdf-sdk"},
	}

	resp, err := http.PostForm(baseURL+"/token", form)
	if err != nil {
		t.Fatalf("POST /token: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for client using password grant, got %d", resp.StatusCode)
	}
}
