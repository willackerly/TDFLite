// e2e_encrypt_decrypt_test.go — Verifies TDF3 encrypt + decrypt works end-to-end.
//
// This is the "known good" test for TDFLite. It uses the Go SDK directly
// (no otdfctl CLI, no JS SDK) to encrypt data with classification attributes,
// then decrypt with the same user, proving the full pipeline works.
//
// Run against a live TDFLite:
//   TDFLITE_URL=http://localhost:8085 TDFLITE_IDP_URL=http://localhost:15433 go test -v -run TestE2E ./tests/
//
//go:build e2e

package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"testing"

	"github.com/opentdf/platform/sdk"
)

func getPlatformURL(t *testing.T) string {
	t.Helper()
	u := os.Getenv("TDFLITE_URL")
	if u == "" {
		t.Skip("TDFLITE_URL not set")
	}
	return u
}

func getIDPURL(t *testing.T) string {
	t.Helper()
	u := os.Getenv("TDFLITE_IDP_URL")
	if u == "" {
		t.Skip("TDFLITE_IDP_URL not set")
	}
	return u
}

func getToken(t *testing.T, idpURL, clientID, clientSecret string) string {
	t.Helper()
	resp, err := http.PostForm(idpURL+"/token", url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
	})
	if err != nil {
		t.Fatalf("token request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("token request returned %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		t.Fatalf("token response parse: %v", err)
	}
	return tokenResp.AccessToken
}

func TestE2EEncryptDecrypt(t *testing.T) {
	platformURL := getPlatformURL(t)
	idpURL := getIDPURL(t)
	_ = context.Background()

	// Get an OIDC token for the opentdf-sdk admin account.
	token := getToken(t, idpURL, "opentdf-sdk", "secret")
	t.Logf("Got OIDC token (%d chars)", len(token))

	// Create an SDK client using sarah.chen (TOP_SECRET clearance).
	s, err := sdk.New(platformURL,
		sdk.WithTokenEndpoint(idpURL+"/token"),
		sdk.WithClientCredentials("sarah.chen-client", "sarah.chen-secret", nil),
		sdk.WithInsecurePlaintextConn(),
	)
	if err != nil {
		t.Fatalf("SDK init: %v", err)
	}
	defer s.Close()

	_ = token // SDK handles auth internally via WithClientCredentials

	// Encrypt
	plaintext := []byte("Hello from TDFLite E2E test — classified data")
	t.Logf("Encrypting %d bytes", len(plaintext))

	encBuf := &bytes.Buffer{}
	_, err = s.CreateTDF(encBuf,
		bytes.NewReader(plaintext),
		sdk.WithDataAttributes(
			"https://blindpipe.local/attr/classification_level/value/top_secret",
		),
		sdk.WithKasInformation(
			sdk.KASInfo{URL: platformURL + "/kas", PublicKey: ""},
		),
	)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	t.Logf("Encrypted: %d bytes TDF3", encBuf.Len())

	// Decrypt
	decReader, err := s.LoadTDF(bytes.NewReader(encBuf.Bytes()))
	if err != nil {
		t.Fatalf("LoadTDF failed: %v", err)
	}

	decBuf := &bytes.Buffer{}
	_, err = io.Copy(decBuf, decReader)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	t.Logf("Decrypted: %d bytes", decBuf.Len())

	if !bytes.Equal(decBuf.Bytes(), plaintext) {
		t.Fatalf("Plaintext mismatch:\n  got:  %q\n  want: %q", decBuf.String(), string(plaintext))
	}

	t.Log("SUCCESS: TDF3 encrypt/decrypt round-trip verified")
}
