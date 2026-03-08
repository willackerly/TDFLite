// Package loader generates OpenTDF-format configuration for TDFLite.
//
// Rather than implementing the full platform config.Loader interface (which
// has complex internal dependencies), this package takes a simpler approach:
// it generates a YAML config file that the platform's built-in viper-based
// loader can read directly.
package loader

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// TDFLiteConfig holds the computed configuration values that TDFLite
// needs to inject into the OpenTDF platform's config system.
type TDFLiteConfig struct {
	DBHost     string
	DBPort     int
	DBName     string
	DBUser     string
	DBPassword string
	DBSSLMode  string
	DBSchema   string

	AuthIssuer   string
	AuthAudience string

	ServerPort int

	EntityResolutionMode string

	CryptoKeys []CryptoKeyConfig
}

// CryptoKeyConfig describes a KAS key pair for the crypto provider.
type CryptoKeyConfig struct {
	KID        string // key identifier, e.g. "r1" or "e1"
	Algorithm  string // e.g. "rsa:2048" or "ec:secp256r1"
	PrivateKey string // path to PEM file
	Cert       string // path to cert PEM file
}

// DefaultConfig returns a TDFLiteConfig with sensible defaults.
// dataDir must be an absolute path to the data directory where key files
// and the embedded Postgres data reside. Using absolute paths ensures the
// crypto provider works regardless of process CWD (critical for Docker).
func DefaultConfig(dataDir string, pgPort, idpPort, serverPort int) TDFLiteConfig {
	return TDFLiteConfig{
		DBHost:     "localhost",
		DBPort:     pgPort,
		DBName:     "opentdf",
		DBUser:     "postgres",
		DBPassword: "changeme",
		DBSSLMode:  "disable",
		DBSchema:   "opentdf",

		AuthIssuer:   fmt.Sprintf("http://localhost:%d", idpPort),
		AuthAudience: fmt.Sprintf("http://localhost:%d", serverPort),

		ServerPort: serverPort,

		EntityResolutionMode: "claims",

		CryptoKeys: []CryptoKeyConfig{
			{
				KID:        "r1",
				Algorithm:  "rsa:2048",
				PrivateKey: filepath.Join(dataDir, "kas-private.pem"),
				Cert:       filepath.Join(dataDir, "kas-cert.pem"),
			},
			{
				KID:        "e1",
				Algorithm:  "ec:secp256r1",
				PrivateKey: filepath.Join(dataDir, "kas-ec-private.pem"),
				Cert:       filepath.Join(dataDir, "kas-ec-cert.pem"),
			},
		},
	}
}

// openTDFConfig is the YAML structure that the OpenTDF platform's viper-based
// config loader expects. Field names and nesting match the platform's config
// schema exactly.
type openTDFConfig struct {
	DevMode bool     `yaml:"dev_mode"`
	Mode    []string `yaml:"mode"`

	DB dbConfig `yaml:"db"`

	Server serverConfig `yaml:"server"`

	Services servicesConfig `yaml:"services"`
}

type dbConfig struct {
	Host          string `yaml:"host"`
	Port          int    `yaml:"port"`
	Database      string `yaml:"database"`
	User          string `yaml:"user"`
	Password      string `yaml:"password"`
	SSLMode       string `yaml:"sslmode"`
	Schema        string `yaml:"schema"`
	RunMigrations bool   `yaml:"runMigrations"`
}

type serverConfig struct {
	Port           int                  `yaml:"port"`
	Auth           authConfig           `yaml:"auth"`
	TLS            tlsConfig            `yaml:"tls"`
	CORS           corsConfig           `yaml:"cors"`
	GRPC           grpcConfig           `yaml:"grpc"`
	CryptoProvider cryptoProviderConfig `yaml:"cryptoProvider"`
}

type authConfig struct {
	Enabled     bool             `yaml:"enabled"`
	EnforceDPoP bool             `yaml:"enforceDPoP"`
	Audience    string           `yaml:"audience"`
	Issuer      string           `yaml:"issuer"`
	Policy      authPolicyConfig `yaml:"policy"`
}

type authPolicyConfig struct {
	ClientIDClaim string `yaml:"client_id_claim"`
	UsernameClaim string `yaml:"username_claim"`
	GroupsClaim   string `yaml:"groups_claim"`
}

type tlsConfig struct {
	Enabled bool `yaml:"enabled"`
}

type corsConfig struct {
	Enabled        bool     `yaml:"enabled"`
	AllowedOrigins []string `yaml:"allowedorigins"`
}

type grpcConfig struct {
	ReflectionEnabled bool `yaml:"reflectionEnabled"`
}

type cryptoProviderConfig struct {
	Type     string               `yaml:"type"`
	Standard cryptoStandardConfig `yaml:"standard"`
}

type cryptoStandardConfig struct {
	Keys []cryptoKeyYAML `yaml:"keys"`
}

type cryptoKeyYAML struct {
	KID     string `yaml:"kid"`
	Alg     string `yaml:"alg"`
	Private string `yaml:"private"`
	Cert    string `yaml:"cert"`
}

type servicesConfig struct {
	EntityResolution entityResolutionConfig `yaml:"entityresolution"`
	KAS              kasServiceConfig       `yaml:"kas"`
	Policy           policyConfig           `yaml:"policy"`
}

type kasServiceConfig struct {
	ECTDFEnabled bool `yaml:"ec_tdf_enabled"`
}

type entityResolutionConfig struct {
	Mode string `yaml:"mode"`
}

type policyConfig struct {
	ListRequestLimitMax     int `yaml:"list_request_limit_max"`
	ListRequestLimitDefault int `yaml:"list_request_limit_default"`
}

// toOpenTDFConfig converts a TDFLiteConfig into the nested YAML structure
// that the OpenTDF platform expects.
func toOpenTDFConfig(cfg TDFLiteConfig) openTDFConfig {
	keys := make([]cryptoKeyYAML, len(cfg.CryptoKeys))
	for i, k := range cfg.CryptoKeys {
		keys[i] = cryptoKeyYAML{
			KID:     k.KID,
			Alg:     k.Algorithm,
			Private: k.PrivateKey,
			Cert:    k.Cert,
		}
	}

	return openTDFConfig{
		DevMode: true,
		Mode:    []string{"all"},
		DB: dbConfig{
			Host:          cfg.DBHost,
			Port:          cfg.DBPort,
			Database:      cfg.DBName,
			User:          cfg.DBUser,
			Password:      cfg.DBPassword,
			SSLMode:       cfg.DBSSLMode,
			Schema:        cfg.DBSchema,
			RunMigrations: true,
		},
		Server: serverConfig{
			Port: cfg.ServerPort,
			Auth: authConfig{
				Enabled:     true,
				EnforceDPoP: false,
				Audience:    cfg.AuthAudience,
				Issuer:      cfg.AuthIssuer,
				Policy: authPolicyConfig{
					ClientIDClaim: "client_id",
					UsernameClaim: "preferred_username",
					GroupsClaim:   "realm_access.roles",
				},
			},
			TLS: tlsConfig{Enabled: false},
			CORS: corsConfig{
				Enabled:        true,
				AllowedOrigins: []string{"*"},
			},
			GRPC: grpcConfig{ReflectionEnabled: true},
			CryptoProvider: cryptoProviderConfig{
				Type:     "standard",
				Standard: cryptoStandardConfig{Keys: keys},
			},
		},
		Services: servicesConfig{
			EntityResolution: entityResolutionConfig{Mode: cfg.EntityResolutionMode},
			KAS:              kasServiceConfig{ECTDFEnabled: true},
			Policy: policyConfig{
				ListRequestLimitMax:     2500,
				ListRequestLimitDefault: 1000,
			},
		},
	}
}

// WriteConfigFile writes a complete OpenTDF-format YAML config file that the
// platform's built-in config loader (viper) can read. It creates parent
// directories if they do not exist.
func WriteConfigFile(cfg TDFLiteConfig, path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("loader: creating config directory %s: %w", dir, err)
	}

	otdfCfg := toOpenTDFConfig(cfg)

	data, err := yaml.Marshal(otdfCfg)
	if err != nil {
		return fmt.Errorf("loader: marshaling config to YAML: %w", err)
	}

	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("loader: writing config file %s: %w", path, err)
	}

	return nil
}
