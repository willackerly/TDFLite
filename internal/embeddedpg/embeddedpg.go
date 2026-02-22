// Package embeddedpg wraps fergusstrange/embedded-postgres to provide
// a managed PostgreSQL instance for TDFLite. It handles lifecycle
// (start/stop), directory creation, and connection URL generation.
package embeddedpg

import (
	"fmt"
	"os"
	"time"

	embeddedpostgres "github.com/fergusstrange/embedded-postgres"
)

// Config holds the configuration for the embedded PostgreSQL server.
type Config struct {
	Port         uint32
	Database     string
	Username     string
	Password     string
	DataPath     string        // e.g. "data/postgres"
	CachePath    string        // e.g. "data/cache"
	StartTimeout time.Duration // time to wait for Postgres to start (first run downloads ~25MB binary)
}

// DefaultConfig returns a Config with sensible defaults for TDFLite.
func DefaultConfig() Config {
	return Config{
		Port:         15432,
		Database:     "opentdf",
		Username:     "postgres",
		Password:     "changeme",
		DataPath:     "data/postgres",
		CachePath:    "data/cache",
		StartTimeout: 60 * time.Second,
	}
}

// Server manages an embedded PostgreSQL instance.
type Server struct {
	pg      *embeddedpostgres.EmbeddedPostgres
	config  Config
	running bool
}

// New creates a new Server with the given configuration. It does not start
// PostgreSQL; call Start() to begin serving.
func New(cfg Config) *Server {
	pg := embeddedpostgres.NewDatabase(
		embeddedpostgres.DefaultConfig().
			Version(embeddedpostgres.V16).
			Port(cfg.Port).
			Database(cfg.Database).
			Username(cfg.Username).
			Password(cfg.Password).
			DataPath(cfg.DataPath).
			CachePath(cfg.CachePath).
			StartTimeout(cfg.StartTimeout),
	)

	return &Server{
		pg:     pg,
		config: cfg,
	}
}

// Start starts the embedded PostgreSQL instance and blocks until it is ready
// to accept connections. It creates DataPath and CachePath directories if they
// do not exist.
func (s *Server) Start() error {
	if s.running {
		return fmt.Errorf("embeddedpg: server is already running")
	}

	// Ensure data and cache directories exist.
	if err := os.MkdirAll(s.config.DataPath, 0o755); err != nil {
		return fmt.Errorf("embeddedpg: creating data directory: %w", err)
	}
	if err := os.MkdirAll(s.config.CachePath, 0o755); err != nil {
		return fmt.Errorf("embeddedpg: creating cache directory: %w", err)
	}

	// Write any build-time-embedded Postgres tarball into the cache directory
	// so the library finds it and skips downloading from the internet.
	if err := PrepopulateCache(s.config.CachePath); err != nil {
		return fmt.Errorf("embeddedpg: prepopulating cache: %w", err)
	}

	if err := s.pg.Start(); err != nil {
		return fmt.Errorf("embeddedpg: starting postgres: %w", err)
	}

	s.running = true
	return nil
}

// Stop gracefully stops the embedded PostgreSQL instance.
func (s *Server) Stop() error {
	if !s.running {
		return fmt.Errorf("embeddedpg: server is not running")
	}

	if err := s.pg.Stop(); err != nil {
		return fmt.Errorf("embeddedpg: stopping postgres: %w", err)
	}

	s.running = false
	return nil
}

// ConnectionURL returns a standard postgres:// connection URL suitable for
// use with pgx and other PostgreSQL drivers.
func (s *Server) ConnectionURL() string {
	return fmt.Sprintf(
		"postgres://%s:%s@localhost:%d/%s?sslmode=disable",
		s.config.Username,
		s.config.Password,
		s.config.Port,
		s.config.Database,
	)
}

// Running reports whether the embedded PostgreSQL instance is currently running.
func (s *Server) Running() bool {
	return s.running
}
