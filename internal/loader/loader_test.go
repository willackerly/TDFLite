package loader

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig(15432, 15433, 8080)

	if cfg.DBHost != "localhost" {
		t.Errorf("DBHost = %q, want %q", cfg.DBHost, "localhost")
	}
	if cfg.DBPort != 15432 {
		t.Errorf("DBPort = %d, want 15432", cfg.DBPort)
	}
	if cfg.DBName != "opentdf" {
		t.Errorf("DBName = %q, want %q", cfg.DBName, "opentdf")
	}
	if cfg.DBUser != "postgres" {
		t.Errorf("DBUser = %q, want %q", cfg.DBUser, "postgres")
	}
	if cfg.DBPassword != "changeme" {
		t.Errorf("DBPassword = %q, want %q", cfg.DBPassword, "changeme")
	}
	if cfg.DBSSLMode != "disable" {
		t.Errorf("DBSSLMode = %q, want %q", cfg.DBSSLMode, "disable")
	}
	if cfg.DBSchema != "opentdf" {
		t.Errorf("DBSchema = %q, want %q", cfg.DBSchema, "opentdf")
	}
	if cfg.AuthIssuer != "http://localhost:15433" {
		t.Errorf("AuthIssuer = %q, want %q", cfg.AuthIssuer, "http://localhost:15433")
	}
	if cfg.AuthAudience != "http://localhost:8080" {
		t.Errorf("AuthAudience = %q, want %q", cfg.AuthAudience, "http://localhost:8080")
	}
	if cfg.ServerPort != 8080 {
		t.Errorf("ServerPort = %d, want 8080", cfg.ServerPort)
	}
	if cfg.EntityResolutionMode != "claims" {
		t.Errorf("EntityResolutionMode = %q, want %q", cfg.EntityResolutionMode, "claims")
	}
	if len(cfg.CryptoKeys) != 2 {
		t.Fatalf("CryptoKeys length = %d, want 2", len(cfg.CryptoKeys))
	}

	// Check RSA key config.
	rsa := cfg.CryptoKeys[0]
	if rsa.KID != "r1" {
		t.Errorf("CryptoKeys[0].KID = %q, want %q", rsa.KID, "r1")
	}
	if rsa.Algorithm != "rsa:2048" {
		t.Errorf("CryptoKeys[0].Algorithm = %q, want %q", rsa.Algorithm, "rsa:2048")
	}

	// Check EC key config.
	ec := cfg.CryptoKeys[1]
	if ec.KID != "e1" {
		t.Errorf("CryptoKeys[1].KID = %q, want %q", ec.KID, "e1")
	}
	if ec.Algorithm != "ec:secp256r1" {
		t.Errorf("CryptoKeys[1].Algorithm = %q, want %q", ec.Algorithm, "ec:secp256r1")
	}
}

func TestDefaultConfigCustomPorts(t *testing.T) {
	cfg := DefaultConfig(5432, 9090, 3000)

	if cfg.DBPort != 5432 {
		t.Errorf("DBPort = %d, want 5432", cfg.DBPort)
	}
	if cfg.AuthIssuer != "http://localhost:9090" {
		t.Errorf("AuthIssuer = %q, want %q", cfg.AuthIssuer, "http://localhost:9090")
	}
	if cfg.AuthAudience != "http://localhost:3000" {
		t.Errorf("AuthAudience = %q, want %q", cfg.AuthAudience, "http://localhost:3000")
	}
	if cfg.ServerPort != 3000 {
		t.Errorf("ServerPort = %d, want 3000", cfg.ServerPort)
	}
}

func TestWriteConfigFileCreatesValidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "subdir", "tdflite.yaml")

	cfg := DefaultConfig(15432, 15433, 8080)
	if err := WriteConfigFile(cfg, path); err != nil {
		t.Fatalf("WriteConfigFile() error: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading written config file: %v", err)
	}

	// Verify it's valid YAML by unmarshaling into a generic map.
	var parsed map[string]any
	if err := yaml.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("written config is not valid YAML: %v", err)
	}
}

func TestWriteConfigFileContainsRequiredFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tdflite.yaml")

	cfg := DefaultConfig(15432, 15433, 8080)
	if err := WriteConfigFile(cfg, path); err != nil {
		t.Fatalf("WriteConfigFile() error: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading written config file: %v", err)
	}

	content := string(data)

	// Check all required top-level and nested fields that the OpenTDF
	// platform config loader expects.
	requiredStrings := []string{
		"dev_mode: true",
		"mode:",
		"- all",
		"db:",
		"host: localhost",
		"port: 15432",
		"database: opentdf",
		"user: postgres",
		"password: changeme",
		"sslmode: disable",
		"schema: opentdf",
		"runMigrations: true",
		"server:",
		"port: 8080",
		"auth:",
		"enabled: true",
		"enforceDPoP: false",
		"audience: http://localhost:8080",
		"issuer: http://localhost:15433",
		"client_id_claim: client_id",
		"username_claim: preferred_username",
		"groups_claim: realm_access.roles",
		"tls:",
		"cors:",
		"allowedorigins:",
		"grpc:",
		"reflectionEnabled: true",
		"cryptoProvider:",
		"type: standard",
		"standard:",
		"keys:",
		"kid: r1",
		"alg: rsa:2048",
		"private: data/kas-private.pem",
		"cert: data/kas-cert.pem",
		"kid: e1",
		"alg: ec:secp256r1",
		"private: data/kas-ec-private.pem",
		"cert: data/kas-ec-cert.pem",
		"services:",
		"entityresolution:",
		"mode: claims",
		"policy:",
		"list_request_limit_max: 2500",
		"list_request_limit_default: 1000",
	}

	for _, s := range requiredStrings {
		if !strings.Contains(content, s) {
			t.Errorf("config file missing required string: %q", s)
		}
	}
}

func TestWriteConfigFileStructure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tdflite.yaml")

	cfg := DefaultConfig(15432, 15433, 8080)
	if err := WriteConfigFile(cfg, path); err != nil {
		t.Fatalf("WriteConfigFile() error: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading written config file: %v", err)
	}

	// Unmarshal into the exact structure to verify field mapping.
	var otdfCfg openTDFConfig
	if err := yaml.Unmarshal(data, &otdfCfg); err != nil {
		t.Fatalf("unmarshaling config into openTDFConfig: %v", err)
	}

	if !otdfCfg.DevMode {
		t.Error("DevMode should be true")
	}
	if len(otdfCfg.Mode) != 1 || otdfCfg.Mode[0] != "all" {
		t.Errorf("Mode = %v, want [all]", otdfCfg.Mode)
	}
	if otdfCfg.DB.Host != "localhost" {
		t.Errorf("DB.Host = %q, want %q", otdfCfg.DB.Host, "localhost")
	}
	if otdfCfg.DB.Port != 15432 {
		t.Errorf("DB.Port = %d, want 15432", otdfCfg.DB.Port)
	}
	if !otdfCfg.DB.RunMigrations {
		t.Error("DB.RunMigrations should be true")
	}
	if otdfCfg.Server.Port != 8080 {
		t.Errorf("Server.Port = %d, want 8080", otdfCfg.Server.Port)
	}
	if !otdfCfg.Server.Auth.Enabled {
		t.Error("Server.Auth.Enabled should be true")
	}
	if otdfCfg.Server.Auth.Issuer != "http://localhost:15433" {
		t.Errorf("Server.Auth.Issuer = %q, want %q", otdfCfg.Server.Auth.Issuer, "http://localhost:15433")
	}
	if otdfCfg.Server.TLS.Enabled {
		t.Error("Server.TLS.Enabled should be false")
	}
	if !otdfCfg.Server.CORS.Enabled {
		t.Error("Server.CORS.Enabled should be true")
	}
	if len(otdfCfg.Server.CryptoProvider.Standard.Keys) != 2 {
		t.Fatalf("CryptoProvider.Standard.Keys length = %d, want 2",
			len(otdfCfg.Server.CryptoProvider.Standard.Keys))
	}
	if otdfCfg.Services.EntityResolution.Mode != "claims" {
		t.Errorf("Services.EntityResolution.Mode = %q, want %q",
			otdfCfg.Services.EntityResolution.Mode, "claims")
	}
	if otdfCfg.Services.Policy.ListRequestLimitMax != 2500 {
		t.Errorf("Services.Policy.ListRequestLimitMax = %d, want 2500",
			otdfCfg.Services.Policy.ListRequestLimitMax)
	}
	if otdfCfg.Services.Policy.ListRequestLimitDefault != 1000 {
		t.Errorf("Services.Policy.ListRequestLimitDefault = %d, want 1000",
			otdfCfg.Services.Policy.ListRequestLimitDefault)
	}
}

func TestWriteConfigFileCreatesDirectories(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a", "b", "c", "tdflite.yaml")

	cfg := DefaultConfig(15432, 15433, 8080)
	if err := WriteConfigFile(cfg, path); err != nil {
		t.Fatalf("WriteConfigFile() error: %v", err)
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Error("WriteConfigFile() did not create the config file")
	}
}
