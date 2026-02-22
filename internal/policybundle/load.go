package policybundle

import (
	"encoding/json"
	"fmt"
	"os"
)

// LoadFile reads a policy bundle from a JSON file at the given path.
// It unmarshals the JSON and runs validation. Returns an error if the
// file cannot be read, the JSON is malformed, or validation fails.
func LoadFile(path string) (*Bundle, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading policy bundle: %w", err)
	}
	return LoadJSON(data)
}

// LoadJSON parses a policy bundle from raw JSON bytes.
// It unmarshals the JSON and runs validation.
func LoadJSON(data []byte) (*Bundle, error) {
	var b Bundle
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("parsing policy bundle JSON: %w", err)
	}
	if err := b.Validate(); err != nil {
		return nil, err
	}
	return &b, nil
}
