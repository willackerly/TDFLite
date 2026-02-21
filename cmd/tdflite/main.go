// TDFLite wraps the OpenTDF platform with embedded PostgreSQL and a built-in OIDC IdP.
// Zero Docker, zero Keycloak, one binary.
//
// Usage:
//
//	tdflite serve [--config path/to/config.yaml] [--data-dir ./data]
//	tdflite version
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/willackerly/TDFLite/internal/embeddedpg"
	"github.com/willackerly/TDFLite/internal/idplite"
	"github.com/willackerly/TDFLite/internal/keygen"
	"github.com/willackerly/TDFLite/internal/loader"

	"github.com/opentdf/platform/service/pkg/server"
)

var version = "dev"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "serve":
		if err := runServe(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "version":
		fmt.Printf("tdflite %s\n", version)
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	configPath := fs.String("config", "", "path to config file (default: auto-generated)")
	dataDir := fs.String("data-dir", "data", "directory for runtime state (keys, postgres, etc.)")
	pgPort := fs.Int("pg-port", 15432, "embedded PostgreSQL port")
	idpPort := fs.Int("idp-port", 15433, "built-in OIDC IdP port")
	platformPort := fs.Int("port", 8080, "OpenTDF platform server port")
	if err := fs.Parse(args); err != nil {
		return err
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	logger.Info("TDFLite starting",
		"version", version,
		"data_dir", *dataDir,
		"pg_port", *pgPort,
		"idp_port", *idpPort,
		"platform_port", *platformPort,
	)

	// Set up signal handling for graceful shutdown.
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Step 1: Generate KAS keys if needed.
	logger.Info("ensuring KAS key pairs exist", "dir", *dataDir)
	if err := keygen.EnsureKeys(*dataDir); err != nil {
		return fmt.Errorf("generating KAS keys: %w", err)
	}
	logger.Info("KAS keys ready")

	// Step 2: Start embedded PostgreSQL.
	pgCfg := embeddedpg.DefaultConfig()
	pgCfg.Port = uint32(*pgPort)
	pgCfg.DataPath = filepath.Join(*dataDir, "postgres")
	pgCfg.CachePath = filepath.Join(*dataDir, "cache")

	pg := embeddedpg.New(pgCfg)
	logger.Info("starting embedded PostgreSQL", "port", pgCfg.Port)
	if err := pg.Start(); err != nil {
		return fmt.Errorf("starting embedded postgres: %w", err)
	}
	defer func() {
		logger.Info("stopping embedded PostgreSQL")
		if err := pg.Stop(); err != nil {
			logger.Error("error stopping postgres", "error", err)
		}
	}()
	logger.Info("embedded PostgreSQL ready", "url", pg.ConnectionURL())

	// Step 3: Start idplite OIDC IdP.
	idpCfg := idplite.Config{
		Issuer:         fmt.Sprintf("http://localhost:%d", *idpPort),
		Audience:       fmt.Sprintf("http://localhost:%d", *platformPort),
		Port:           *idpPort,
		SigningKeyPath: filepath.Join(*dataDir, "idp-signing-key.pem"),
		IdentityFile:   filepath.Join(*dataDir, "identity.json"),
		TokenTTL:       5 * time.Minute,
	}

	idp, err := idplite.New(idpCfg)
	if err != nil {
		return fmt.Errorf("creating idplite: %w", err)
	}

	logger.Info("starting idplite OIDC IdP", "issuer", idpCfg.Issuer)
	if err := idp.Start(ctx); err != nil {
		return fmt.Errorf("starting idplite: %w", err)
	}
	defer func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		logger.Info("stopping idplite")
		if err := idp.Stop(shutdownCtx); err != nil {
			logger.Error("error stopping idplite", "error", err)
		}
	}()
	logger.Info("idplite OIDC IdP ready", "addr", idp.Addr())

	// Step 4: Generate OpenTDF platform config.
	cfgFile := *configPath
	if cfgFile == "" {
		// Generate a config file pointing at our embedded infrastructure.
		loaderCfg := loader.DefaultConfig(*pgPort, *idpPort, *platformPort)

		cfgFile = filepath.Join(*dataDir, "opentdf.yaml")
		logger.Info("generating OpenTDF config", "path", cfgFile)
		if err := loader.WriteConfigFile(loaderCfg, cfgFile); err != nil {
			return fmt.Errorf("writing config file: %w", err)
		}
	}

	// Step 5: Start OpenTDF platform.
	logger.Info("starting OpenTDF platform",
		"config", cfgFile,
		"port", *platformPort,
	)

	// server.Start() blocks until shutdown signal or error.
	// It handles its own signal handling via WithWaitForShutdownSignal().
	if err := server.Start(
		server.WithConfigFile(cfgFile),
		server.WithWaitForShutdownSignal(),
	); err != nil {
		return fmt.Errorf("platform server: %w", err)
	}

	logger.Info("TDFLite stopped")
	return nil
}

func printUsage() {
	fmt.Println(`TDFLite - OpenTDF Platform, Zero Infrastructure

Usage:
  tdflite <command> [flags]

Commands:
  serve     Start TDFLite (embedded-postgres + idplite + OpenTDF platform)
  version   Print version information
  help      Show this help

Flags (serve):
  --config    Path to OpenTDF YAML config file (default: auto-generated)
  --data-dir  Directory for runtime state (default: ./data)
  --pg-port   Embedded PostgreSQL port (default: 15432)
  --idp-port  Built-in OIDC IdP port (default: 15433)
  --port      OpenTDF platform server port (default: 8080)`)
}
