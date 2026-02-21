package embeddedpg

import (
	"strings"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Port != 15432 {
		t.Errorf("Port = %d, want 15432", cfg.Port)
	}
	if cfg.Database != "opentdf" {
		t.Errorf("Database = %q, want %q", cfg.Database, "opentdf")
	}
	if cfg.Username != "postgres" {
		t.Errorf("Username = %q, want %q", cfg.Username, "postgres")
	}
	if cfg.Password != "changeme" {
		t.Errorf("Password = %q, want %q", cfg.Password, "changeme")
	}
	if cfg.DataPath != "data/postgres" {
		t.Errorf("DataPath = %q, want %q", cfg.DataPath, "data/postgres")
	}
	if cfg.CachePath != "data/cache" {
		t.Errorf("CachePath = %q, want %q", cfg.CachePath, "data/cache")
	}
	if cfg.StartTimeout != 60*time.Second {
		t.Errorf("StartTimeout = %v, want %v", cfg.StartTimeout, 60*time.Second)
	}
}

func TestConnectionURL(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
		want string
	}{
		{
			name: "default config",
			cfg:  DefaultConfig(),
			want: "postgres://postgres:changeme@localhost:15432/opentdf?sslmode=disable",
		},
		{
			name: "custom config",
			cfg: Config{
				Port:     5432,
				Database: "mydb",
				Username: "admin",
				Password: "secret",
			},
			want: "postgres://admin:secret@localhost:5432/mydb?sslmode=disable",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := New(tt.cfg)
			got := s.ConnectionURL()
			if got != tt.want {
				t.Errorf("ConnectionURL() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestConnectionURLFormat(t *testing.T) {
	s := New(DefaultConfig())
	url := s.ConnectionURL()

	if !strings.HasPrefix(url, "postgres://") {
		t.Errorf("ConnectionURL() should start with postgres://, got %q", url)
	}
	if !strings.Contains(url, "sslmode=disable") {
		t.Errorf("ConnectionURL() should contain sslmode=disable, got %q", url)
	}
	if !strings.Contains(url, "localhost:15432") {
		t.Errorf("ConnectionURL() should contain localhost:15432, got %q", url)
	}
}

func TestNewDoesNotStart(t *testing.T) {
	cfg := DefaultConfig()
	s := New(cfg)

	if s.Running() {
		t.Error("New() should not start the server")
	}
	if s.pg == nil {
		t.Error("New() should initialize the embedded postgres instance")
	}
}

func TestStopWithoutStartReturnsError(t *testing.T) {
	s := New(DefaultConfig())

	err := s.Stop()
	if err == nil {
		t.Error("Stop() on a non-running server should return an error")
	}
}

// Integration tests for Start/Stop are intentionally omitted from unit tests.
// Starting embedded PostgreSQL downloads a ~25MB binary on first run and takes
// several seconds. These should be covered by integration tests in tests/ with
// a build tag (e.g., //go:build integration).
