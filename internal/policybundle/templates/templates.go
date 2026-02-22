// Package templates provides built-in policy templates that are embedded in the
// TDFLite binary. These templates can be used during first-run setup to quickly
// bootstrap a policy bundle for common use cases (healthcare, finance, defense).
package templates

import (
	"embed"
	"encoding/json"
	"fmt"

	"github.com/willackerly/TDFLite/internal/policybundle"
)

//go:embed healthcare.json finance.json defense.json
var templateFS embed.FS

// Available returns the names of all available templates.
func Available() []string {
	return []string{"healthcare", "finance", "defense"}
}

// Descriptions returns human-readable descriptions for each template.
func Descriptions() map[string]string {
	return map[string]string{
		"healthcare": "HIPAA-oriented healthcare policy (physicians, nurses, billing, researchers)",
		"finance":    "SOX/financial data policy (trading, compliance, risk, audit)",
		"defense":    "US defense/IC classification (TS/SCI, SAP, FVEY releasability)",
	}
}

// Load returns a policy bundle from the named template.
func Load(name string) (*policybundle.Bundle, error) {
	filename := name + ".json"
	data, err := templateFS.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("template %q not found: %w", name, err)
	}

	var bundle policybundle.Bundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		return nil, fmt.Errorf("parsing template %q: %w", name, err)
	}

	if err := bundle.Validate(); err != nil {
		return nil, fmt.Errorf("invalid template %q: %w", name, err)
	}

	return &bundle, nil
}
