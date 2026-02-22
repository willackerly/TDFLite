package policybundle

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	"golang.org/x/crypto/ssh"
)

// canonicalBytes returns the deterministic JSON representation of the bundle
// with the Signature field cleared. This is the byte sequence that gets signed
// or hashed during seal operations.
func canonicalBytes(b *Bundle) ([]byte, error) {
	// Make a shallow copy and clear the signature so it's not part of the
	// signed payload.
	cp := *b
	cp.Signature = ""
	data, err := json.Marshal(&cp)
	if err != nil {
		return nil, fmt.Errorf("marshaling canonical bundle: %w", err)
	}
	return data, nil
}

// SignBundle signs the bundle using an SSH private key file. The signature
// covers all fields except Signature itself. Supported key types: Ed25519,
// RSA, and ECDSA.
//
// After signing, bundle.Signature is set to the base64-encoded signature.
func SignBundle(bundle *Bundle, sshPrivKeyPath string) error {
	keyData, err := os.ReadFile(sshPrivKeyPath)
	if err != nil {
		return fmt.Errorf("reading SSH private key: %w", err)
	}

	rawKey, err := ssh.ParseRawPrivateKey(keyData)
	if err != nil {
		return fmt.Errorf("parsing SSH private key: %w", err)
	}

	canonical, err := canonicalBytes(bundle)
	if err != nil {
		return err
	}

	sig, err := signBytes(canonical, rawKey)
	if err != nil {
		return err
	}

	bundle.Signature = base64.StdEncoding.EncodeToString(sig)
	return nil
}

// signBytes produces a raw signature over data using the given private key.
func signBytes(data []byte, privKey interface{}) ([]byte, error) {
	switch k := privKey.(type) {
	case ed25519.PrivateKey:
		return ed25519.Sign(k, data), nil

	case *ed25519.PrivateKey:
		return ed25519.Sign(*k, data), nil

	case *rsa.PrivateKey:
		h := sha256.Sum256(data)
		return rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, h[:])

	case *ecdsa.PrivateKey:
		h := sha256.Sum256(data)
		return ecdsa.SignASN1(rand.Reader, k, h[:])

	default:
		return nil, fmt.Errorf("unsupported SSH key type: %T", privKey)
	}
}

// SignBundlePassphrase computes a tamper-detection hash for passphrase-sealed
// bundles. Since there is no asymmetric key, this uses SHA-256 over the
// canonical bytes. This provides tamper detection (an attacker must recompute
// the hash after modification) but NOT authentication -- anyone who can read
// the bundle can recompute the hash. This tradeoff is acceptable for
// passphrase mode, which targets demos and simple deployments.
func SignBundlePassphrase(bundle *Bundle) error {
	canonical, err := canonicalBytes(bundle)
	if err != nil {
		return err
	}

	h := sha256.Sum256(canonical)
	bundle.Signature = base64.StdEncoding.EncodeToString(h[:])
	return nil
}

// VerifySignature verifies the bundle's signature using an SSH public key file
// (authorized_keys format). Returns nil if the signature is valid, or an error
// describing the failure.
func VerifySignature(bundle *Bundle, sshPubKeyPath string) error {
	if bundle.Signature == "" {
		return fmt.Errorf("bundle has no signature")
	}

	pubKeyData, err := os.ReadFile(sshPubKeyPath)
	if err != nil {
		return fmt.Errorf("reading SSH public key: %w", err)
	}

	sshPub, _, _, _, err := ssh.ParseAuthorizedKey(pubKeyData)
	if err != nil {
		return fmt.Errorf("parsing SSH public key: %w", err)
	}

	// Extract the underlying crypto.PublicKey from the ssh.PublicKey.
	cryptoPub, ok := sshPub.(ssh.CryptoPublicKey)
	if !ok {
		return fmt.Errorf("SSH public key does not implement CryptoPublicKey")
	}
	pubKey := cryptoPub.CryptoPublicKey()

	sigBytes, err := base64.StdEncoding.DecodeString(bundle.Signature)
	if err != nil {
		return fmt.Errorf("decoding signature: %w", err)
	}

	canonical, err := canonicalBytes(bundle)
	if err != nil {
		return err
	}

	return verifyBytes(canonical, sigBytes, pubKey)
}

// verifyBytes checks a raw signature against canonical data and a public key.
func verifyBytes(data, sig []byte, pubKey interface{}) error {
	switch k := pubKey.(type) {
	case ed25519.PublicKey:
		if !ed25519.Verify(k, data, sig) {
			return fmt.Errorf("ed25519 signature verification failed")
		}
		return nil

	case *rsa.PublicKey:
		h := sha256.Sum256(data)
		if err := rsa.VerifyPKCS1v15(k, crypto.SHA256, h[:], sig); err != nil {
			return fmt.Errorf("RSA signature verification failed: %w", err)
		}
		return nil

	case *ecdsa.PublicKey:
		h := sha256.Sum256(data)
		if !ecdsa.VerifyASN1(k, h[:], sig) {
			return fmt.Errorf("ECDSA signature verification failed")
		}
		return nil

	default:
		return fmt.Errorf("unsupported public key type: %T", pubKey)
	}
}

// VerifyPassphraseSignature verifies a passphrase-mode bundle's tamper-detection
// hash. Recomputes SHA-256 over the canonical bytes and compares with the stored
// signature.
func VerifyPassphraseSignature(bundle *Bundle) error {
	if bundle.Signature == "" {
		return fmt.Errorf("bundle has no signature")
	}

	canonical, err := canonicalBytes(bundle)
	if err != nil {
		return err
	}

	h := sha256.Sum256(canonical)
	expected := base64.StdEncoding.EncodeToString(h[:])

	if bundle.Signature != expected {
		return fmt.Errorf("passphrase signature verification failed: hash mismatch")
	}
	return nil
}
