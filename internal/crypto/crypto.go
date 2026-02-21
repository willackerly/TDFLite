// Package crypto defines the cryptographic operations interface for TDFLite.
//
// The default implementation uses Go's standard library crypto packages
// (crypto/rsa, crypto/ecdsa, crypto/aes). Swap in PKCS#11 HSM, AWS KMS,
// or HashiCorp Vault Transit by implementing this interface.
package crypto

import (
	"context"
	"crypto"
)

// Algorithm identifies a key algorithm.
type Algorithm string

const (
	AlgorithmRSA2048    Algorithm = "rsa:2048"
	AlgorithmECSecp256r1 Algorithm = "ec:secp256r1"
)

// KeyPair represents an asymmetric key pair.
type KeyPair struct {
	ID         string          `json:"id"`
	Algorithm  Algorithm       `json:"algorithm"`
	PublicKey  crypto.PublicKey `json:"-"`
	PrivateKey crypto.PrivateKey `json:"-"`
	PublicPEM  string          `json:"public_pem"`
}

// Provider performs cryptographic operations.
// Implementations must be safe for concurrent use.
type Provider interface {
	// GenerateKeyPair generates a new asymmetric key pair.
	GenerateKeyPair(ctx context.Context, algorithm Algorithm) (*KeyPair, error)

	// GetKeyPair retrieves a key pair by ID.
	GetKeyPair(ctx context.Context, id string) (*KeyPair, error)

	// Encrypt encrypts data with a public key (RSA-OAEP or ECIES).
	Encrypt(ctx context.Context, keyID string, plaintext []byte) ([]byte, error)

	// Decrypt decrypts data with a private key.
	Decrypt(ctx context.Context, keyID string, ciphertext []byte) ([]byte, error)

	// SymmetricEncrypt encrypts data with AES-256-GCM.
	SymmetricEncrypt(key, plaintext, aad []byte) (ciphertext, nonce []byte, err error)

	// SymmetricDecrypt decrypts data with AES-256-GCM.
	SymmetricDecrypt(key, ciphertext, nonce, aad []byte) ([]byte, error)

	// ExportPublicKey exports a public key in PEM format.
	ExportPublicKey(ctx context.Context, keyID string) (string, error)
}
