// Package embeddedpg provides optional embedding of PostgreSQL binary tarballs.
//
// At build time, if .txz files are present in the pgcache/ directory, they are
// compiled into the binary via //go:embed. At runtime, PrepopulateCache writes
// them to the library's cache directory so embedded-postgres skips downloading.
//
// If no .txz files are present at build time (the default), PrepopulateCache
// is a no-op and the library downloads as usual.
//
// To embed the Postgres binary:
//
//	bash scripts/fetch-postgres.sh   # places .txz in pgcache/
//	go build -o tdflite ./cmd/tdflite
package embeddedpg

import (
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// pgcacheFS embeds the pgcache directory. The "all:" prefix ensures hidden
// files like .gitkeep are included, which guarantees the embed directive
// always succeeds even when no .txz files are present.
//
//go:embed all:pgcache
var pgcacheFS embed.FS

// PrepopulateCache writes any embedded .txz files from the compiled binary
// into cachePath so that embedded-postgres finds them and skips downloading.
//
// If no .txz files were embedded at build time, this is a no-op.
// If a file already exists at the destination, it is not overwritten.
func PrepopulateCache(cachePath string) error {
	entries, err := fs.ReadDir(pgcacheFS, "pgcache")
	if err != nil {
		return fmt.Errorf("embeddedpg: reading embedded pgcache: %w", err)
	}

	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".txz") {
			continue
		}

		destPath := filepath.Join(cachePath, name)

		// Skip if already present on disk.
		if _, statErr := os.Stat(destPath); statErr == nil {
			continue
		}

		data, readErr := pgcacheFS.ReadFile(filepath.Join("pgcache", name))
		if readErr != nil {
			return fmt.Errorf("embeddedpg: reading embedded file %s: %w", name, readErr)
		}

		if writeErr := os.WriteFile(destPath, data, 0o644); writeErr != nil {
			return fmt.Errorf("embeddedpg: writing cache file %s: %w", destPath, writeErr)
		}
	}

	return nil
}
