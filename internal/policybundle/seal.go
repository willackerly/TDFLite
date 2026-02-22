package policybundle

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"golang.org/x/crypto/ssh"
)

// KASKeys holds the decrypted key material extracted from a sealed bundle.
type KASKeys struct {
	RSAPrivate *rsa.PrivateKey
	RSACert    []byte // PEM-encoded self-signed certificate
	ECPrivate  *ecdsa.PrivateKey
	ECCert     []byte // PEM-encoded self-signed certificate
	IDPKey     *rsa.PrivateKey
}

// sealWorkFactor is the scrypt work factor for passphrase sealing.
// Set low (10) for tests; production callers can override before sealing.
var sealWorkFactor = 18

// SetSealWorkFactor overrides the scrypt work factor used by passphrase sealing.
// Use a low value (e.g. 10) in tests for speed. The default production value is 18.
func SetSealWorkFactor(n int) {
	sealWorkFactor = n
}

// SealWithSSHKey generates KAS and IdP keys, encrypts them with the given SSH
// public key via age, and populates bundle.Sealed. The Signature field is NOT
// set here -- that is handled separately by sign.go.
func SealWithSSHKey(bundle *Bundle, sshPubKeyPath string) error {
	// Read and parse the SSH public key.
	pubKeyData, err := os.ReadFile(sshPubKeyPath)
	if err != nil {
		return fmt.Errorf("reading SSH public key: %w", err)
	}

	recipient, err := agessh.ParseRecipient(strings.TrimSpace(string(pubKeyData)))
	if err != nil {
		return fmt.Errorf("parsing SSH public key as age recipient: %w", err)
	}

	// Compute SSH fingerprint.
	sshPubKey, _, _, _, err := ssh.ParseAuthorizedKey(pubKeyData)
	if err != nil {
		return fmt.Errorf("parsing SSH public key for fingerprint: %w", err)
	}
	fingerprint := ssh.FingerprintSHA256(sshPubKey)

	// Generate keys and seal.
	if err := sealWithRecipient(bundle, recipient); err != nil {
		return err
	}

	bundle.Sealed.Fingerprint = fingerprint
	bundle.Sealed.Method = "" // defaults to "ssh"
	return nil
}

// SealWithPassphrase generates KAS and IdP keys, encrypts them with a
// passphrase-derived key via age/scrypt, and populates bundle.Sealed.
func SealWithPassphrase(bundle *Bundle, passphrase string) error {
	recipient, err := age.NewScryptRecipient(passphrase)
	if err != nil {
		return fmt.Errorf("creating scrypt recipient: %w", err)
	}
	recipient.SetWorkFactor(sealWorkFactor)

	if err := sealWithRecipient(bundle, recipient); err != nil {
		return err
	}

	bundle.Sealed.Fingerprint = ""
	bundle.Sealed.Method = "passphrase"
	return nil
}

// UnsealWithSSHKey decrypts the sealed key material using an SSH private key.
func UnsealWithSSHKey(bundle *Bundle, sshPrivKeyPath string) (KASKeys, error) {
	if bundle.Sealed == nil {
		return KASKeys{}, fmt.Errorf("bundle is not sealed")
	}

	privKeyData, err := os.ReadFile(sshPrivKeyPath)
	if err != nil {
		return KASKeys{}, fmt.Errorf("reading SSH private key: %w", err)
	}

	identity, err := agessh.ParseIdentity(privKeyData)
	if err != nil {
		return KASKeys{}, fmt.Errorf("parsing SSH private key as age identity: %w", err)
	}

	return unsealWithIdentity(bundle, identity)
}

// UnsealWithPassphrase decrypts the sealed key material using a passphrase.
func UnsealWithPassphrase(bundle *Bundle, passphrase string) (KASKeys, error) {
	if bundle.Sealed == nil {
		return KASKeys{}, fmt.Errorf("bundle is not sealed")
	}

	identity, err := age.NewScryptIdentity(passphrase)
	if err != nil {
		return KASKeys{}, fmt.Errorf("creating scrypt identity: %w", err)
	}

	return unsealWithIdentity(bundle, identity)
}

// RebindSSHKey re-encrypts a sealed bundle's key material from one SSH key to
// another. It decrypts with oldPrivKeyPath, then re-encrypts the same key
// material with the public key derived from newPrivKeyPath (+ ".pub"), and
// re-signs with the new private key. The KAS and IdP keys themselves are
// preserved — only the encryption wrapper changes.
func RebindSSHKey(bundle *Bundle, oldPrivKeyPath, newPrivKeyPath string) error {
	if bundle.Sealed == nil {
		return fmt.Errorf("bundle is not sealed")
	}

	// Step 1: Unseal with old key to get raw PEM blobs (not parsed keys,
	// to ensure byte-perfect round-trip we re-serialize from parsed keys).
	keys, err := UnsealWithSSHKey(bundle, oldPrivKeyPath)
	if err != nil {
		return fmt.Errorf("unsealing with old key: %w", err)
	}

	// Step 2: Re-serialize key material to PEM blobs.
	kasBlob := serializeKASKeys(keys.RSAPrivate, keys.RSACert, keys.ECPrivate, keys.ECCert)
	idpBlob := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(keys.IDPKey),
	})

	// Step 3: Read new SSH public key for encryption.
	newPubKeyPath := newPrivKeyPath + ".pub"
	pubKeyData, err := os.ReadFile(newPubKeyPath)
	if err != nil {
		return fmt.Errorf("reading new SSH public key %s: %w", newPubKeyPath, err)
	}

	recipient, err := agessh.ParseRecipient(strings.TrimSpace(string(pubKeyData)))
	if err != nil {
		return fmt.Errorf("parsing new SSH public key as age recipient: %w", err)
	}

	// Compute new fingerprint.
	sshPubKey, _, _, _, err := ssh.ParseAuthorizedKey(pubKeyData)
	if err != nil {
		return fmt.Errorf("parsing new SSH public key for fingerprint: %w", err)
	}
	fingerprint := ssh.FingerprintSHA256(sshPubKey)

	// Step 4: Re-encrypt with new recipient.
	encKAS, err := ageEncrypt(kasBlob, recipient)
	if err != nil {
		return fmt.Errorf("re-encrypting KAS keys: %w", err)
	}

	encIDP, err := ageEncrypt(idpBlob, recipient)
	if err != nil {
		return fmt.Errorf("re-encrypting IdP key: %w", err)
	}

	bundle.Sealed = &Sealed{
		KASKeys:     base64.StdEncoding.EncodeToString(encKAS),
		IDPKey:      base64.StdEncoding.EncodeToString(encIDP),
		Fingerprint: fingerprint,
	}

	// Step 5: Re-sign with new private key.
	if err := SignBundle(bundle, newPrivKeyPath); err != nil {
		return fmt.Errorf("re-signing with new key: %w", err)
	}

	return nil
}

// WriteKeysToDisk writes decrypted KAS keys and IdP signing key to the
// filesystem in the format expected by the OpenTDF platform and idplite.
// KAS private keys are written as PKCS#8 PEM to match keygen.go output.
func WriteKeysToDisk(keys KASKeys, dataDir string) error {
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return fmt.Errorf("creating data dir: %w", err)
	}

	// RSA private key as PKCS#8 (matches keygen.go format).
	rsaPKCS8, err := x509.MarshalPKCS8PrivateKey(keys.RSAPrivate)
	if err != nil {
		return fmt.Errorf("marshaling RSA private key: %w", err)
	}
	rsaKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: rsaPKCS8})
	if err := os.WriteFile(filepath.Join(dataDir, "kas-private.pem"), rsaKeyPEM, 0600); err != nil {
		return fmt.Errorf("writing RSA private key: %w", err)
	}

	// RSA certificate (already PEM-encoded).
	if err := os.WriteFile(filepath.Join(dataDir, "kas-cert.pem"), keys.RSACert, 0644); err != nil {
		return fmt.Errorf("writing RSA certificate: %w", err)
	}

	// EC private key as PKCS#8 (matches keygen.go format).
	ecPKCS8, err := x509.MarshalPKCS8PrivateKey(keys.ECPrivate)
	if err != nil {
		return fmt.Errorf("marshaling EC private key: %w", err)
	}
	ecKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: ecPKCS8})
	if err := os.WriteFile(filepath.Join(dataDir, "kas-ec-private.pem"), ecKeyPEM, 0600); err != nil {
		return fmt.Errorf("writing EC private key: %w", err)
	}

	// EC certificate (already PEM-encoded).
	if err := os.WriteFile(filepath.Join(dataDir, "kas-ec-cert.pem"), keys.ECCert, 0644); err != nil {
		return fmt.Errorf("writing EC certificate: %w", err)
	}

	// IdP signing key as PKCS#1 PEM (matches idplite format).
	idpPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(keys.IDPKey),
	})
	if err := os.WriteFile(filepath.Join(dataDir, "idp-signing-key.pem"), idpPEM, 0600); err != nil {
		return fmt.Errorf("writing IdP signing key: %w", err)
	}

	return nil
}

// sealWithRecipient is the shared implementation for both SSH and passphrase sealing.
func sealWithRecipient(bundle *Bundle, recipient age.Recipient) error {
	// Generate KAS RSA-2048 keypair.
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("generating KAS RSA key: %w", err)
	}

	// Generate KAS EC P-256 keypair.
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generating KAS EC key: %w", err)
	}

	// Generate IdP RSA-2048 signing key.
	idpKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("generating IdP RSA key: %w", err)
	}

	// Create self-signed certs for KAS keys.
	rsaCertPEM, err := selfSignedCert(rsaKey, "TDFLite KAS RSA")
	if err != nil {
		return fmt.Errorf("creating RSA self-signed cert: %w", err)
	}

	ecCertPEM, err := selfSignedCertEC(ecKey, "TDFLite KAS EC")
	if err != nil {
		return fmt.Errorf("creating EC self-signed cert: %w", err)
	}

	// Serialize KAS keys + certs to PEM blob.
	kasBlob := serializeKASKeys(rsaKey, rsaCertPEM, ecKey, ecCertPEM)

	// Serialize IdP key to PEM.
	idpBlob := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(idpKey),
	})

	// Encrypt KAS keys with age.
	encKAS, err := ageEncrypt(kasBlob, recipient)
	if err != nil {
		return fmt.Errorf("encrypting KAS keys: %w", err)
	}

	// Encrypt IdP key with age.
	encIDP, err := ageEncrypt(idpBlob, recipient)
	if err != nil {
		return fmt.Errorf("encrypting IdP key: %w", err)
	}

	bundle.Sealed = &Sealed{
		KASKeys: base64.StdEncoding.EncodeToString(encKAS),
		IDPKey:  base64.StdEncoding.EncodeToString(encIDP),
	}

	return nil
}

// unsealWithIdentity is the shared implementation for both SSH and passphrase unsealing.
func unsealWithIdentity(bundle *Bundle, identity age.Identity) (KASKeys, error) {
	// Decode and decrypt KAS keys.
	kasEnc, err := base64.StdEncoding.DecodeString(bundle.Sealed.KASKeys)
	if err != nil {
		return KASKeys{}, fmt.Errorf("decoding KAS keys: %w", err)
	}

	kasPlain, err := ageDecrypt(kasEnc, identity)
	if err != nil {
		return KASKeys{}, fmt.Errorf("decrypting KAS keys: %w", err)
	}

	// Decode and decrypt IdP key.
	idpEnc, err := base64.StdEncoding.DecodeString(bundle.Sealed.IDPKey)
	if err != nil {
		return KASKeys{}, fmt.Errorf("decoding IdP key: %w", err)
	}

	idpPlain, err := ageDecrypt(idpEnc, identity)
	if err != nil {
		return KASKeys{}, fmt.Errorf("decrypting IdP key: %w", err)
	}

	// Parse the PEM blobs back into key objects.
	keys, err := parseKASKeysBlob(kasPlain)
	if err != nil {
		return KASKeys{}, fmt.Errorf("parsing KAS keys: %w", err)
	}

	idpKey, err := parseIDPKeyBlob(idpPlain)
	if err != nil {
		return KASKeys{}, fmt.Errorf("parsing IdP key: %w", err)
	}
	keys.IDPKey = idpKey

	return keys, nil
}

// ageEncrypt encrypts plaintext to the given recipient using age.
func ageEncrypt(plaintext []byte, recipient age.Recipient) ([]byte, error) {
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, recipient)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(plaintext); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// ageDecrypt decrypts an age-encrypted ciphertext with the given identity.
func ageDecrypt(ciphertext []byte, identity age.Identity) ([]byte, error) {
	r, err := age.Decrypt(bytes.NewReader(ciphertext), identity)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}

// serializeKASKeys produces a PEM blob containing all KAS key material.
// The blob contains labeled sections: RSA private key, RSA cert, EC private key, EC cert.
func serializeKASKeys(rsaKey *rsa.PrivateKey, rsaCert []byte, ecKey *ecdsa.PrivateKey, ecCert []byte) []byte {
	var buf bytes.Buffer

	// RSA private key (PKCS1).
	buf.Write(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(rsaKey),
	}))

	// RSA certificate.
	buf.Write(rsaCert)

	// EC private key.
	ecDER, _ := x509.MarshalECPrivateKey(ecKey)
	buf.Write(pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: ecDER,
	}))

	// EC certificate.
	buf.Write(ecCert)

	return buf.Bytes()
}

// parseKASKeysBlob parses a PEM blob produced by serializeKASKeys.
func parseKASKeysBlob(data []byte) (KASKeys, error) {
	var keys KASKeys
	rest := data

	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}

		switch block.Type {
		case "RSA PRIVATE KEY":
			key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				return KASKeys{}, fmt.Errorf("parsing RSA private key: %w", err)
			}
			if keys.RSAPrivate == nil {
				keys.RSAPrivate = key
			}
			// If we already have an RSA private key, this might be the IdP key,
			// but in the KAS blob we only expect one RSA key.

		case "EC PRIVATE KEY":
			key, err := x509.ParseECPrivateKey(block.Bytes)
			if err != nil {
				return KASKeys{}, fmt.Errorf("parsing EC private key: %w", err)
			}
			keys.ECPrivate = key

		case "CERTIFICATE":
			certPEM := pem.EncodeToMemory(block)
			if keys.RSAPrivate != nil && keys.RSACert == nil {
				keys.RSACert = certPEM
			} else if keys.ECPrivate != nil && keys.ECCert == nil {
				keys.ECCert = certPEM
			}
		}
	}

	if keys.RSAPrivate == nil {
		return KASKeys{}, fmt.Errorf("KAS RSA private key not found in blob")
	}
	if keys.ECPrivate == nil {
		return KASKeys{}, fmt.Errorf("KAS EC private key not found in blob")
	}
	if keys.RSACert == nil {
		return KASKeys{}, fmt.Errorf("KAS RSA certificate not found in blob")
	}
	if keys.ECCert == nil {
		return KASKeys{}, fmt.Errorf("KAS EC certificate not found in blob")
	}

	return keys, nil
}

// parseIDPKeyBlob parses a PEM blob containing a single RSA private key.
func parseIDPKeyBlob(data []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in IdP key blob")
	}
	if block.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("unexpected PEM type %q for IdP key", block.Type)
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing IdP RSA private key: %w", err)
	}
	return key, nil
}

// selfSignedCert creates a self-signed X.509 certificate for an RSA key.
func selfSignedCert(key *rsa.PrivateKey, cn string) ([]byte, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour), // 10 years
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), nil
}

// selfSignedCertEC creates a self-signed X.509 certificate for an ECDSA key.
func selfSignedCertEC(key *ecdsa.PrivateKey, cn string) ([]byte, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour), // 10 years
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), nil
}
