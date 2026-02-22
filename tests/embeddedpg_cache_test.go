package tests_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/willackerly/TDFLite/internal/embeddedpg"
)

// ---------------------------------------------------------------------------
// Embedded PG Cache Tests
// ---------------------------------------------------------------------------

// TestCachePrepopulateNoOp verifies that PrepopulateCache is a no-op when
// no .txz files are embedded at build time (the default for development).
func TestCachePrepopulateNoOp(t *testing.T) {
	t.Run("EmptyEmbedReturnsNil", func(t *testing.T) {
		dir := t.TempDir()
		err := embeddedpg.PrepopulateCache(dir)
		if err != nil {
			t.Fatalf("PrepopulateCache returned error on empty embed: %v", err)
		}

		// Verify no .txz files were written.
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("reading cache dir: %v", err)
		}
		for _, entry := range entries {
			if filepath.Ext(entry.Name()) == ".txz" {
				t.Errorf("unexpected .txz file in cache dir: %s", entry.Name())
			}
		}
	})

	t.Run("CreatesCacheDirIfNeeded", func(t *testing.T) {
		parent := t.TempDir()
		cacheDir := filepath.Join(parent, "new-cache-dir")

		// The directory does not exist yet.
		if _, err := os.Stat(cacheDir); !os.IsNotExist(err) {
			t.Fatalf("expected cache dir to not exist, got: %v", err)
		}

		// PrepopulateCache should NOT create the directory itself --
		// it only writes files, not directories. The caller (Start) creates
		// the dir. But PrepopulateCache should not error on a nonexistent
		// dir with no files to write (it's a no-op).
		//
		// Actually, let's test what happens: if PrepopulateCache tries to
		// write a file to a nonexistent dir, that would fail. But since
		// there are no .txz files to write (empty embed), it should succeed
		// even if the directory doesn't exist.
		err := embeddedpg.PrepopulateCache(cacheDir)
		if err != nil {
			t.Fatalf("PrepopulateCache returned error on nonexistent dir (no-op case): %v", err)
		}
	})

	t.Run("ExistingDirIsUnmodified", func(t *testing.T) {
		dir := t.TempDir()

		// Create a pre-existing file to ensure PrepopulateCache doesn't delete it.
		existingFile := filepath.Join(dir, "existing.txt")
		if err := os.WriteFile(existingFile, []byte("keep me"), 0644); err != nil {
			t.Fatalf("creating existing file: %v", err)
		}

		err := embeddedpg.PrepopulateCache(dir)
		if err != nil {
			t.Fatalf("PrepopulateCache: %v", err)
		}

		// Verify the existing file is still there and untouched.
		data, err := os.ReadFile(existingFile)
		if err != nil {
			t.Fatalf("reading existing file after PrepopulateCache: %v", err)
		}
		if string(data) != "keep me" {
			t.Fatalf("existing file was modified: got %q", string(data))
		}
	})

	t.Run("IdempotentOnRepeatedCalls", func(t *testing.T) {
		dir := t.TempDir()

		// Call twice -- should be idempotent.
		if err := embeddedpg.PrepopulateCache(dir); err != nil {
			t.Fatalf("first PrepopulateCache: %v", err)
		}
		if err := embeddedpg.PrepopulateCache(dir); err != nil {
			t.Fatalf("second PrepopulateCache: %v", err)
		}

		// Verify no files were written.
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("reading cache dir: %v", err)
		}
		for _, entry := range entries {
			if filepath.Ext(entry.Name()) == ".txz" {
				t.Errorf("unexpected .txz file in cache dir after idempotent calls: %s", entry.Name())
			}
		}
	})

	t.Run("SkipLogicWithDummyTxzFile", func(t *testing.T) {
		// Test the skip-existing-file logic: if a .txz file already exists
		// on disk at the destination path, PrepopulateCache should skip it.
		// Since we can't embed a real .txz at test time, we create a dummy
		// file that would collide IF there were an embedded file of the same
		// name. The actual result is that PrepopulateCache iterates zero
		// .txz entries from the embed, so the dummy file is simply ignored.
		dir := t.TempDir()

		dummyTxz := filepath.Join(dir, "embedded-postgres-binaries-linux-amd64-16.txz")
		if err := os.WriteFile(dummyTxz, []byte("fake tarball"), 0644); err != nil {
			t.Fatalf("creating dummy .txz: %v", err)
		}

		err := embeddedpg.PrepopulateCache(dir)
		if err != nil {
			t.Fatalf("PrepopulateCache with pre-existing .txz: %v", err)
		}

		// Verify the dummy file was not overwritten or deleted.
		data, err := os.ReadFile(dummyTxz)
		if err != nil {
			t.Fatalf("reading dummy .txz: %v", err)
		}
		if string(data) != "fake tarball" {
			t.Fatalf("dummy .txz was modified: got %q", string(data))
		}
	})
}

// TestCacheDefaultConfig verifies the DefaultConfig returns expected values
// that PrepopulateCache would use.
func TestCacheDefaultConfig(t *testing.T) {
	cfg := embeddedpg.DefaultConfig()

	if cfg.Port != 15432 {
		t.Errorf("expected default port 15432, got %d", cfg.Port)
	}
	if cfg.Database != "opentdf" {
		t.Errorf("expected default database 'opentdf', got %q", cfg.Database)
	}
	if cfg.CachePath != "data/cache" {
		t.Errorf("expected default cache path 'data/cache', got %q", cfg.CachePath)
	}
}
