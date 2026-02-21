// Package config handles loading and validating TDFLite configuration.
package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config is the top-level TDFLite configuration.
type Config struct {
	Server  ServerConfig  `yaml:"server"`
	Store   StoreConfig   `yaml:"store"`
	Auth    AuthConfig    `yaml:"auth"`
	KAS     KASConfig     `yaml:"kas"`
	Logging LoggingConfig `yaml:"logging"`
}

// ServerConfig configures the HTTP/gRPC server.
type ServerConfig struct {
	Port int    `yaml:"port"`
	Host string `yaml:"host"`
	TLS  struct {
		Enabled  bool   `yaml:"enabled"`
		CertFile string `yaml:"cert_file"`
		KeyFile  string `yaml:"key_file"`
	} `yaml:"tls"`
}

// StoreConfig configures the persistence backend.
type StoreConfig struct {
	// Type is the store backend: "memory", "jsonfile".
	Type    string `yaml:"type"`
	DataDir string `yaml:"data_dir"`
}

// AuthConfig configures authentication.
type AuthConfig struct {
	// Enabled controls whether authentication is enforced.
	Enabled bool `yaml:"enabled"`
	// Provider is the auth provider type: "builtin", "external".
	Provider string `yaml:"provider"`
	// Issuer is the OIDC issuer URL (for external providers).
	Issuer string `yaml:"issuer"`
	// Audience is the expected token audience.
	Audience string `yaml:"audience"`
	// BuiltinIDP configures the built-in lightweight IdP.
	BuiltinIDP struct {
		IdentityFile string `yaml:"identity_file"`
	} `yaml:"builtin_idp"`
}

// KASConfig configures the Key Access Server.
type KASConfig struct {
	// DefaultAlgorithm is the default key algorithm: "rsa:2048", "ec:secp256r1".
	DefaultAlgorithm string `yaml:"default_algorithm"`
	// CryptoProvider is the crypto backend: "software", "hsm", "kms".
	CryptoProvider string `yaml:"crypto_provider"`
}

// LoggingConfig configures logging.
type LoggingConfig struct {
	Level  string `yaml:"level"`  // "debug", "info", "warn", "error"
	Format string `yaml:"format"` // "text", "json"
}

// Load reads configuration from a YAML file, with environment variable overrides.
func Load(path string) (*Config, error) {
	cfg := defaults()

	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("reading config file: %w", err)
		}
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("parsing config file: %w", err)
		}
	}

	// Environment variable overrides.
	if v := os.Getenv("TDFLITE_PORT"); v != "" {
		fmt.Sscanf(v, "%d", &cfg.Server.Port)
	}
	if v := os.Getenv("TDFLITE_DATA_DIR"); v != "" {
		cfg.Store.DataDir = v
	}
	if v := os.Getenv("TDFLITE_LOG_LEVEL"); v != "" {
		cfg.Logging.Level = v
	}

	return cfg, nil
}

func defaults() *Config {
	return &Config{
		Server: ServerConfig{
			Port: 8080,
			Host: "0.0.0.0",
		},
		Store: StoreConfig{
			Type:    "memory",
			DataDir: "./data",
		},
		Auth: AuthConfig{
			Enabled:  true,
			Provider: "builtin",
			Audience: "https://tdflite.local",
		},
		KAS: KASConfig{
			DefaultAlgorithm: "rsa:2048",
			CryptoProvider:   "software",
		},
		Logging: LoggingConfig{
			Level:  "info",
			Format: "text",
		},
	}
}
