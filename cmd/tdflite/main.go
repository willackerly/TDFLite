// TDFLite wraps the OpenTDF platform with embedded PostgreSQL and a built-in OIDC IdP.
// Zero Docker, zero Keycloak, one binary.
//
// Usage:
//
//	tdflite up [--template healthcare|finance|defense] [--ssh-key ~/.ssh/id_ed25519]
//	tdflite serve [--config path/to/config.yaml] [--data-dir ./data]
//	tdflite policy seal --policy policy.json [--ssh-key ~/.ssh/id_ed25519.pub]
//	tdflite policy rebind --policy policy.sealed.json --old-key ... --new-key ...
//	tdflite version
package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/willackerly/TDFLite/internal/embeddedpg"
	"github.com/willackerly/TDFLite/internal/idplite"
	"github.com/willackerly/TDFLite/internal/keygen"
	"github.com/willackerly/TDFLite/internal/loader"
	"github.com/willackerly/TDFLite/internal/policybundle"
	"github.com/willackerly/TDFLite/internal/policybundle/templates"
	"github.com/willackerly/TDFLite/internal/provision"

	"golang.org/x/crypto/ssh"

	"github.com/opentdf/platform/service/pkg/server"
)

var version = "dev"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "up":
		if err := runUp(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "serve":
		if err := runServe(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "policy":
		if len(os.Args) < 3 {
			fmt.Fprintf(os.Stderr, "error: policy requires a subcommand (seal, rebind)\n")
			printUsage()
			os.Exit(1)
		}
		switch os.Args[2] {
		case "seal":
			if err := runPolicySeal(os.Args[3:]); err != nil {
				fmt.Fprintf(os.Stderr, "error: %v\n", err)
				os.Exit(1)
			}
		case "rebind":
			if err := runPolicyRebind(os.Args[3:]); err != nil {
				fmt.Fprintf(os.Stderr, "error: %v\n", err)
				os.Exit(1)
			}
		default:
			fmt.Fprintf(os.Stderr, "unknown policy subcommand: %s\n", os.Args[2])
			printUsage()
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

// ---------------------------------------------------------------------------
// up — interactive cold start wizard
// ---------------------------------------------------------------------------

func runUp(args []string) error {
	fs := flag.NewFlagSet("up", flag.ExitOnError)
	templateFlag := fs.String("template", "", "template name (healthcare, finance, defense) or path to JSON file")
	sshKeyFlag := fs.String("ssh-key", "", "path to SSH private key (default: ~/.ssh/id_ed25519)")
	dataDirFlag := fs.String("data-dir", "data", "data directory")
	portFlag := fs.Int("port", 8080, "platform port")
	pgPortFlag := fs.Int("pg-port", 15432, "embedded PostgreSQL port")
	idpPortFlag := fs.Int("idp-port", 15433, "built-in OIDC IdP port")
	outputFlag := fs.String("output", "policy.sealed.json", "output path for sealed bundle")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// Step 1: Welcome banner.
	fmt.Println()
	fmt.Println("TDFLite — Zero-Infrastructure Data Protection")
	fmt.Println()
	fmt.Println("This wizard will get you running in under 60 seconds.")
	fmt.Println("No Docker. No Keycloak. One file + your SSH key.")
	fmt.Println()

	// Step 2: SSH key detection / generation.
	privKeyPath := *sshKeyFlag
	if privKeyPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("finding home directory: %w", err)
		}
		privKeyPath = filepath.Join(home, ".ssh", "id_ed25519")
	}
	pubKeyPath := privKeyPath + ".pub"

	privExists := fileExists(privKeyPath)
	pubExists := fileExists(pubKeyPath)

	if privExists && pubExists {
		fmt.Printf("Found SSH key: %s\n", privKeyPath)
	} else {
		fmt.Printf("No SSH key found at %s — generating one...\n", privKeyPath)
		if err := generateSSHKeyPair(privKeyPath, pubKeyPath); err != nil {
			return fmt.Errorf("generating SSH keypair: %w", err)
		}
		fmt.Printf("Generated new SSH keypair: %s\n", privKeyPath)
	}
	fmt.Println()

	// Step 3: Template selection.
	var bundle *policybundle.Bundle

	if *templateFlag != "" {
		// Non-interactive: use the flag value.
		var err error
		bundle, err = loadTemplateOrFile(*templateFlag)
		if err != nil {
			return err
		}
	} else {
		// Interactive: prompt the user.
		available := templates.Available()
		descriptions := templates.Descriptions()

		fmt.Println("Choose a policy template:")
		fmt.Println()
		for i, name := range available {
			desc := descriptions[name]
			// Pad the name for alignment.
			label := strings.Title(name) //nolint:staticcheck
			fmt.Printf("  [%d] %-12s — %s\n", i+1, label, desc)
		}
		fmt.Printf("  [%d] %-12s — Load from a JSON file\n", len(available)+1, "Custom")
		fmt.Println()
		fmt.Printf("Enter choice [1-%d]: ", len(available)+1)

		line, err := stdinReader.ReadString('\n')
		if err != nil && line == "" {
			return fmt.Errorf("reading choice: %w", err)
		}
		line = strings.TrimSpace(line)

		choice, err := strconv.Atoi(line)
		if err != nil || choice < 1 || choice > len(available)+1 {
			return fmt.Errorf("invalid choice: %q (expected 1-%d)", line, len(available)+1)
		}

		if choice <= len(available) {
			// Built-in template.
			name := available[choice-1]
			fmt.Printf("Loading template: %s\n", name)
			bundle, err = templates.Load(name)
			if err != nil {
				return fmt.Errorf("loading template %q: %w", name, err)
			}
		} else {
			// Custom file.
			fmt.Print("Path to policy JSON file: ")
			fileLine, err := stdinReader.ReadString('\n')
			if err != nil && fileLine == "" {
				return fmt.Errorf("reading file path: %w", err)
			}
			filePath := strings.TrimSpace(fileLine)
			bundle, err = policybundle.LoadFile(filePath)
			if err != nil {
				return fmt.Errorf("loading custom policy: %w", err)
			}
		}
	}

	fmt.Printf("Policy: %d attributes, %d identities\n", len(bundle.Attributes), len(bundle.Identities))
	fmt.Println()

	// Step 4: Seal the bundle.
	fmt.Println("Sealing policy bundle...")
	if err := policybundle.SealWithSSHKey(bundle, pubKeyPath); err != nil {
		return fmt.Errorf("sealing with SSH key: %w", err)
	}
	if err := policybundle.SignBundle(bundle, privKeyPath); err != nil {
		return fmt.Errorf("signing bundle: %w", err)
	}

	// Write sealed bundle to disk.
	data, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling sealed bundle: %w", err)
	}
	if err := os.WriteFile(*outputFlag, append(data, '\n'), 0600); err != nil {
		return fmt.Errorf("writing sealed bundle: %w", err)
	}

	fmt.Printf("Sealed policy bundle: %s (fingerprint: %s)\n", *outputFlag, bundle.Sealed.Fingerprint)
	fmt.Println()

	// Step 5: Auto-detect port conflicts.
	pgPort := *pgPortFlag
	if !portAvailable(pgPort) {
		old := pgPort
		pgPort = findFreePort(pgPort)
		fmt.Printf("Port %d in use — using %d for PostgreSQL\n", old, pgPort)
	}
	idpPort := *idpPortFlag
	if !portAvailable(idpPort) {
		old := idpPort
		idpPort = findFreePort(idpPort)
		fmt.Printf("Port %d in use — using %d for OIDC IdP\n", old, idpPort)
	}
	platformPort := *portFlag
	if !portAvailable(platformPort) {
		old := platformPort
		platformPort = findFreePort(platformPort)
		fmt.Printf("Port %d in use — using %d for platform\n", old, platformPort)
	}

	// Step 6: Boot the platform.
	fmt.Println()
	fmt.Println("Starting TDFLite platform...")
	fmt.Println()

	serveArgs := []string{
		"--policy", *outputFlag,
		"--key", privKeyPath,
		"--data-dir", *dataDirFlag,
		"--port", strconv.Itoa(platformPort),
		"--pg-port", strconv.Itoa(pgPort),
		"--idp-port", strconv.Itoa(idpPort),
	}
	return runServe(serveArgs)
}

// loadTemplateOrFile loads a policy bundle from a named template or a file path.
func loadTemplateOrFile(nameOrPath string) (*policybundle.Bundle, error) {
	// Check if it's a known template name.
	for _, t := range templates.Available() {
		if strings.EqualFold(nameOrPath, t) {
			fmt.Printf("Loading template: %s\n", t)
			return templates.Load(t)
		}
	}

	// Otherwise, treat as a file path.
	fmt.Printf("Loading custom policy: %s\n", nameOrPath)
	return policybundle.LoadFile(nameOrPath)
}

// generateSSHKeyPair creates an Ed25519 SSH keypair and writes it to disk.
// Creates the parent directory with 0700 permissions if it doesn't exist.
func generateSSHKeyPair(privPath, pubPath string) error {
	// Ensure the directory exists.
	dir := filepath.Dir(privPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("creating SSH directory %s: %w", dir, err)
	}

	// Generate Ed25519 keypair.
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generating ed25519 key: %w", err)
	}

	// Marshal private key to OpenSSH PEM format.
	privPEM, err := ssh.MarshalPrivateKey(privKey, "")
	if err != nil {
		return fmt.Errorf("marshaling private key: %w", err)
	}
	if err := os.WriteFile(privPath, pem.EncodeToMemory(privPEM), 0600); err != nil {
		return fmt.Errorf("writing private key: %w", err)
	}

	// Marshal public key to authorized_keys format.
	sshPub, err := ssh.NewPublicKey(pubKey)
	if err != nil {
		return fmt.Errorf("creating SSH public key: %w", err)
	}
	if err := os.WriteFile(pubPath, ssh.MarshalAuthorizedKey(sshPub), 0644); err != nil {
		return fmt.Errorf("writing public key: %w", err)
	}

	return nil
}

// fileExists reports whether the named file exists and is a regular file.
func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// ---------------------------------------------------------------------------
// policy seal
// ---------------------------------------------------------------------------

func runPolicySeal(args []string) error {
	fs := flag.NewFlagSet("policy seal", flag.ExitOnError)
	policyPath := fs.String("policy", "", "path to plain policy.json (required)")
	sshKeyPath := fs.String("ssh-key", "", "path to SSH public key (default: ~/.ssh/id_ed25519.pub)")
	usePassphrase := fs.Bool("passphrase", false, "use passphrase mode instead of SSH key")
	outputPath := fs.String("output", "policy.sealed.json", "output path for sealed bundle")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *policyPath == "" {
		return fmt.Errorf("--policy is required")
	}

	// Load and validate the plain policy.
	bundle, err := policybundle.LoadFile(*policyPath)
	if err != nil {
		return fmt.Errorf("loading policy: %w", err)
	}
	fmt.Printf("loaded policy: %d attributes, %d identities\n", len(bundle.Attributes), len(bundle.Identities))

	if *usePassphrase {
		// Passphrase mode: prompt for passphrase.
		passphrase, err := readPassphrase("Enter passphrase for sealing: ")
		if err != nil {
			return fmt.Errorf("reading passphrase: %w", err)
		}
		confirm, err := readPassphrase("Confirm passphrase: ")
		if err != nil {
			return fmt.Errorf("reading passphrase confirmation: %w", err)
		}
		if passphrase != confirm {
			return fmt.Errorf("passphrases do not match")
		}

		fmt.Println("sealing with passphrase...")
		if err := policybundle.SealWithPassphrase(bundle, passphrase); err != nil {
			return fmt.Errorf("sealing: %w", err)
		}
		if err := policybundle.SignBundlePassphrase(bundle); err != nil {
			return fmt.Errorf("signing: %w", err)
		}
		fmt.Println("sealed with passphrase (SHA-256 tamper detection)")
	} else {
		// SSH key mode.
		pubKeyPath := *sshKeyPath
		if pubKeyPath == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				return fmt.Errorf("finding home directory: %w", err)
			}
			pubKeyPath = filepath.Join(home, ".ssh", "id_ed25519.pub")
		}

		// Derive private key path for signing (strip .pub).
		privKeyPath := strings.TrimSuffix(pubKeyPath, ".pub")
		if privKeyPath == pubKeyPath {
			return fmt.Errorf("SSH key path %q does not end in .pub; cannot derive private key path for signing", pubKeyPath)
		}

		fmt.Printf("sealing with SSH key: %s\n", pubKeyPath)
		if err := policybundle.SealWithSSHKey(bundle, pubKeyPath); err != nil {
			return fmt.Errorf("sealing: %w", err)
		}

		if err := policybundle.SignBundle(bundle, privKeyPath); err != nil {
			return fmt.Errorf("signing: %w", err)
		}
		fmt.Printf("sealed and signed (fingerprint: %s)\n", bundle.Sealed.Fingerprint)
	}

	// Write sealed bundle to output.
	data, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling sealed bundle: %w", err)
	}

	if err := os.WriteFile(*outputPath, append(data, '\n'), 0600); err != nil {
		return fmt.Errorf("writing sealed bundle: %w", err)
	}

	fmt.Printf("wrote sealed bundle to %s\n", *outputPath)
	return nil
}

// ---------------------------------------------------------------------------
// policy rebind
// ---------------------------------------------------------------------------

func runPolicyRebind(args []string) error {
	fs := flag.NewFlagSet("policy rebind", flag.ExitOnError)
	policyPath := fs.String("policy", "", "path to sealed policy file (required)")
	oldKeyPath := fs.String("old-key", "", "path to old SSH private key (required)")
	newKeyPath := fs.String("new-key", "", "path to new SSH private key (required)")
	outputPath := fs.String("output", "", "output path (default: overwrites input)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *policyPath == "" {
		return fmt.Errorf("--policy is required")
	}
	if *oldKeyPath == "" {
		return fmt.Errorf("--old-key is required")
	}
	if *newKeyPath == "" {
		return fmt.Errorf("--new-key is required")
	}

	outPath := *outputPath
	if outPath == "" {
		outPath = *policyPath
	}

	// Load the sealed bundle.
	bundle, err := policybundle.LoadFile(*policyPath)
	if err != nil {
		return fmt.Errorf("loading sealed policy: %w", err)
	}
	if !bundle.IsSealed() {
		return fmt.Errorf("policy file is not sealed")
	}

	fmt.Printf("rebinding sealed bundle from old key to new key...\n")
	fmt.Printf("  old key: %s\n", *oldKeyPath)
	fmt.Printf("  new key: %s\n", *newKeyPath)

	if err := policybundle.RebindSSHKey(bundle, *oldKeyPath, *newKeyPath); err != nil {
		return fmt.Errorf("rebinding: %w", err)
	}

	// Write output.
	data, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling rebound bundle: %w", err)
	}

	if err := os.WriteFile(outPath, append(data, '\n'), 0600); err != nil {
		return fmt.Errorf("writing rebound bundle: %w", err)
	}

	fmt.Printf("rebound bundle written to %s (fingerprint: %s)\n", outPath, bundle.Sealed.Fingerprint)
	return nil
}

// ---------------------------------------------------------------------------
// serve
// ---------------------------------------------------------------------------

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	configPath := fs.String("config", "", "path to config file (default: auto-generated)")
	dataDir := fs.String("data-dir", "data", "directory for runtime state (keys, postgres, etc.)")
	pgPort := fs.Int("pg-port", 15432, "embedded PostgreSQL port")
	idpPort := fs.Int("idp-port", 15433, "built-in OIDC IdP port")
	platformPort := fs.Int("port", 8080, "OpenTDF platform server port")
	policyPath := fs.String("policy", "", "path to sealed policy bundle")
	keyPath := fs.String("key", "", "path to SSH private key for unsealing (default: ~/.ssh/id_ed25519)")
	usePassphrase := fs.Bool("passphrase", false, "use passphrase mode for unsealing")
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

	// If --policy is provided, unseal and extract keys from the policy bundle.
	var bundle *policybundle.Bundle
	if *policyPath != "" {
		logger.Info("loading sealed policy bundle", "path", *policyPath)
		var err error
		bundle, err = policybundle.LoadFile(*policyPath)
		if err != nil {
			return fmt.Errorf("loading policy bundle: %w", err)
		}
		if !bundle.IsSealed() {
			return fmt.Errorf("policy file %s is not sealed", *policyPath)
		}

		// Verify signature.
		if *usePassphrase {
			logger.Info("verifying passphrase signature")
			if err := policybundle.VerifyPassphraseSignature(bundle); err != nil {
				return fmt.Errorf("signature verification failed: %w", err)
			}
		} else {
			sshPrivKey := *keyPath
			if sshPrivKey == "" {
				home, err := os.UserHomeDir()
				if err != nil {
					return fmt.Errorf("finding home directory: %w", err)
				}
				sshPrivKey = filepath.Join(home, ".ssh", "id_ed25519")
			}
			sshPubKey := sshPrivKey + ".pub"

			logger.Info("verifying SSH signature", "pub_key", sshPubKey)
			if err := policybundle.VerifySignature(bundle, sshPubKey); err != nil {
				return fmt.Errorf("signature verification failed: %w", err)
			}
		}
		logger.Info("signature verified")

		// Unseal to get KAS keys.
		var keys policybundle.KASKeys
		if *usePassphrase {
			passphrase, err := readPassphrase("Enter passphrase to unseal: ")
			if err != nil {
				return fmt.Errorf("reading passphrase: %w", err)
			}
			keys, err = policybundle.UnsealWithPassphrase(bundle, passphrase)
			if err != nil {
				return fmt.Errorf("unsealing with passphrase: %w", err)
			}
		} else {
			sshPrivKey := *keyPath
			if sshPrivKey == "" {
				home, err := os.UserHomeDir()
				if err != nil {
					return fmt.Errorf("finding home directory: %w", err)
				}
				sshPrivKey = filepath.Join(home, ".ssh", "id_ed25519")
			}

			logger.Info("unsealing with SSH key", "key", sshPrivKey)
			var err error
			keys, err = policybundle.UnsealWithSSHKey(bundle, sshPrivKey)
			if err != nil {
				return fmt.Errorf("unsealing with SSH key: %w", err)
			}
		}
		logger.Info("bundle unsealed, writing keys to data dir")

		// Write KAS keys and IdP key to data dir.
		if err := policybundle.WriteKeysToDisk(keys, *dataDir); err != nil {
			return fmt.Errorf("writing keys to disk: %w", err)
		}

		// Generate identities from the bundle and write to data dir.
		identities, err := policybundle.GenerateIdentities(bundle)
		if err != nil {
			return fmt.Errorf("generating identities: %w", err)
		}
		identityData, err := json.MarshalIndent(identities, "", "  ")
		if err != nil {
			return fmt.Errorf("marshaling identities: %w", err)
		}
		identityPath := filepath.Join(*dataDir, "identity.json")
		if err := os.WriteFile(identityPath, identityData, 0600); err != nil {
			return fmt.Errorf("writing identity file: %w", err)
		}
		logger.Info("keys and identities written", "identity_file", identityPath)
	} else {
		// No policy bundle — generate keys the traditional way.
		logger.Info("ensuring KAS key pairs exist", "dir", *dataDir)
		if err := keygen.EnsureKeys(*dataDir); err != nil {
			return fmt.Errorf("generating KAS keys: %w", err)
		}
		logger.Info("KAS keys ready")
	}

	// Start embedded PostgreSQL.
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

	// Start idplite OIDC IdP.
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

	// Generate OpenTDF platform config.
	cfgFile := *configPath
	if cfgFile == "" {
		loaderCfg := loader.DefaultConfig(*pgPort, *idpPort, *platformPort)

		cfgFile = filepath.Join(*dataDir, "opentdf.yaml")
		logger.Info("generating OpenTDF config", "path", cfgFile)
		if err := loader.WriteConfigFile(loaderCfg, cfgFile); err != nil {
			return fmt.Errorf("writing config file: %w", err)
		}
	}

	// If a policy bundle was loaded, start provisioning in background after
	// the platform becomes healthy.
	if bundle != nil {
		idpURL := fmt.Sprintf("http://localhost:%d", *idpPort)
		platformURL := fmt.Sprintf("http://localhost:%d", *platformPort)
		provBundle := bundle
		go func() {
			provisionAfterHealthy(ctx, logger, platformURL, idpURL, provBundle, *platformPort)
		}()
	}

	// Start OpenTDF platform (blocks until shutdown).
	logger.Info("starting OpenTDF platform",
		"config", cfgFile,
		"port", *platformPort,
	)
	if err := server.Start(
		server.WithConfigFile(cfgFile),
		server.WithWaitForShutdownSignal(),
	); err != nil {
		return fmt.Errorf("platform server: %w", err)
	}

	logger.Info("TDFLite stopped")
	return nil
}

// provisionAfterHealthy waits for the platform health endpoint to respond,
// then provisions policy from the bundle.
func provisionAfterHealthy(ctx context.Context, logger *slog.Logger, platformURL, idpURL string, bundle *policybundle.Bundle, platformPort int) {
	healthURL := fmt.Sprintf("http://localhost:%d/healthz", platformPort)

	logger.Info("waiting for platform health check", "url", healthURL)
	for i := 0; i < 120; i++ {
		select {
		case <-ctx.Done():
			logger.Warn("context cancelled while waiting for health check")
			return
		default:
		}

		resp, err := http.Get(healthURL)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				logger.Info("platform is healthy, starting provisioning")
				break
			}
		}
		if i == 119 {
			logger.Error("platform did not become healthy within 120 seconds, skipping provisioning")
			return
		}
		time.Sleep(time.Second)
	}

	// Get admin auth token.
	token, err := provision.GetAuthToken(ctx, idpURL)
	if err != nil {
		logger.Error("failed to get auth token for provisioning", "error", err)
		return
	}

	// Provision the policy.
	if err := provision.Provision(ctx, bundle, platformURL, token); err != nil {
		logger.Error("provisioning failed", "error", err)
		return
	}

	logger.Info("policy provisioned successfully")
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// portAvailable checks whether a TCP port can be listened on.
func portAvailable(port int) bool {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return false
	}
	ln.Close()
	return true
}

// findFreePort returns an available TCP port. It asks the OS for one by
// listening on :0, which assigns an ephemeral port.
func findFreePort(preferred int) int {
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		return preferred // fallback — let the caller deal with it
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return port
}

// stdinReader is a package-level buffered reader for stdin. Using a single
// reader avoids the problem where multiple bufio.Scanner instances each
// consume and buffer data independently, causing reads after the first to fail.
var stdinReader = bufio.NewReader(os.Stdin)

// readPassphrase reads a passphrase from stdin. Note: input is NOT hidden
// from the terminal. For production use, consider golang.org/x/term.
func readPassphrase(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	line, err := stdinReader.ReadString('\n')
	if err != nil && line == "" {
		return "", fmt.Errorf("no input: %w", err)
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// ---------------------------------------------------------------------------
// usage
// ---------------------------------------------------------------------------

func printUsage() {
	fmt.Println(`TDFLite - OpenTDF Platform, Zero Infrastructure

Usage:
  tdflite <command> [flags]

Commands:
  up             Interactive cold start — choose a template, seal, and boot
  serve          Start TDFLite (embedded-postgres + idplite + OpenTDF platform)
  policy seal    Seal a plain policy bundle with SSH key or passphrase
  policy rebind  Re-encrypt a sealed bundle with a different SSH key
  version        Print version information
  help           Show this help

Flags (up):
  --template    Template name (healthcare, finance, defense) or path to JSON file
  --ssh-key     Path to SSH private key (default: ~/.ssh/id_ed25519)
  --data-dir    Data directory (default: data)
  --port        Platform port (default: 8080)
  --pg-port     Embedded PostgreSQL port (default: 15432)
  --idp-port    Built-in OIDC IdP port (default: 15433)
  --output      Output path for sealed bundle (default: policy.sealed.json)

Flags (serve):
  --config      Path to OpenTDF YAML config file (default: auto-generated)
  --data-dir    Directory for runtime state (default: ./data)
  --pg-port     Embedded PostgreSQL port (default: 15432)
  --idp-port    Built-in OIDC IdP port (default: 15433)
  --port        OpenTDF platform server port (default: 8080)
  --policy      Path to sealed policy bundle (enables auto-provisioning)
  --key         Path to SSH private key for unsealing (default: ~/.ssh/id_ed25519)
  --passphrase  Use passphrase mode for unsealing (prompted from stdin)

Flags (policy seal):
  --policy      Path to plain policy.json (required)
  --ssh-key     Path to SSH public key (default: ~/.ssh/id_ed25519.pub)
  --passphrase  Use passphrase mode instead of SSH key
  --output      Output path (default: policy.sealed.json)

Flags (policy rebind):
  --policy      Path to sealed policy file (required)
  --old-key     Path to old SSH private key for decryption (required)
  --new-key     Path to new SSH private key for re-encryption (required)
  --output      Output path (default: overwrites input)`)
}
