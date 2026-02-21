// Package tdf provides types and utilities for the Trusted Data Format (TDF).
//
// This is a public API package — it can be imported by external projects.
// It covers both TDF3 (JSON manifest + encrypted payload) and NanoTDF
// (compact binary format for constrained environments).
package tdf

// Manifest is the TDF3 JSON manifest describing the encrypted payload.
type Manifest struct {
	// EncryptionInformation describes how the payload is encrypted.
	EncryptionInformation EncryptionInformation `json:"encryptionInformation"`
	// Payload describes the encrypted payload.
	Payload PayloadReference `json:"payload"`
}

// EncryptionInformation describes the encryption method and key access.
type EncryptionInformation struct {
	// Type identifies the encryption scheme (e.g., "split").
	Type string `json:"type"`
	// Policy is the base64-encoded policy object.
	Policy string `json:"policy"`
	// KeyAccess is the list of key access objects.
	KeyAccess []KeyAccessObject `json:"keyAccess"`
	// Method describes the symmetric encryption method.
	Method EncryptionMethod `json:"method"`
	// IntegrityInformation for payload integrity verification.
	IntegrityInformation IntegrityInformation `json:"integrityInformation"`
}

// KeyAccessObject describes how to access a wrapped key from a KAS.
type KeyAccessObject struct {
	// Type is the key access type (e.g., "wrapped").
	Type string `json:"type"`
	// URL is the KAS endpoint URL.
	URL string `json:"url"`
	// Protocol is the key wrapping protocol (e.g., "kas").
	Protocol string `json:"protocol"`
	// WrappedKey is the base64-encoded DEK wrapped with the KAS public key.
	WrappedKey string `json:"wrappedKey"`
	// PolicyBinding is the HMAC binding the policy to the key.
	PolicyBinding string `json:"policyBinding"`
	// EncryptedMetadata is optional encrypted metadata.
	EncryptedMetadata string `json:"encryptedMetadata,omitempty"`
	// KID is the KAS key identifier.
	KID string `json:"kid,omitempty"`
}

// EncryptionMethod describes the symmetric cipher.
type EncryptionMethod struct {
	// Algorithm is the encryption algorithm (e.g., "AES-256-GCM").
	Algorithm string `json:"algorithm"`
	// IsStreamable indicates if the payload supports streaming decryption.
	IsStreamable bool `json:"isStreamable"`
	// IV is the initialization vector (base64).
	IV string `json:"iv,omitempty"`
}

// IntegrityInformation for verifying payload integrity.
type IntegrityInformation struct {
	RootSignature RootSignature  `json:"rootSignature"`
	SegmentHashAlg string        `json:"segmentHashAlg"`
	Segments      []Segment      `json:"segments,omitempty"`
	SegmentSizeDefault int       `json:"segmentSizeDefault"`
	EncryptedSegmentSizeDefault int `json:"encryptedSegmentSizeDefault"`
}

// RootSignature is the top-level integrity hash.
type RootSignature struct {
	Algorithm string `json:"alg"`
	Signature string `json:"sig"`
}

// Segment is an individual payload segment hash.
type Segment struct {
	Hash          string `json:"hash"`
	SegmentSize   int    `json:"segmentSize,omitempty"`
	EncryptedSegmentSize int `json:"encryptedSegmentSize,omitempty"`
}

// PayloadReference describes the encrypted payload.
type PayloadReference struct {
	Type        string `json:"type"`
	URL         string `json:"url"`
	Protocol    string `json:"protocol"`
	MimeType    string `json:"mimeType"`
	IsEncrypted bool   `json:"isEncrypted"`
}

// Policy is the TDF policy object that governs access.
type Policy struct {
	UUID string     `json:"uuid"`
	Body PolicyBody `json:"body"`
}

// PolicyBody contains the attribute bindings for a TDF.
type PolicyBody struct {
	DataAttributes []DataAttribute `json:"dataAttributes"`
	Dissem         []string        `json:"dissem"`
}

// DataAttribute is an attribute bound to the TDF data.
type DataAttribute struct {
	Attribute string `json:"attribute"`
	DisplayName string `json:"displayName,omitempty"`
	KASUrl    string `json:"kasUrl,omitempty"`
}
