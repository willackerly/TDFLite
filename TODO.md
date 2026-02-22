# TODO

**Last synced:** 2026-02-23

## Phase 0: Wrap-and-Shim — COMPLETE

All tasks done and verified end-to-end. Binary builds, all services start, health endpoint responds, tokens issue.

- [x] 0a. Repo restructure — removed old scaffolding, rewrote go.mod
- [x] 0b. idplite — built-in OIDC IdP (discovery, JWKS, token endpoint)
- [x] 0c. Config loader — YAML generator in OpenTDF format
- [x] 0d. Embedded PostgreSQL wrapper — V16, native ARM64
- [x] 0e. KAS key generation — RSA-2048 + EC P-256, idempotent
- [x] 0f. Default config — tdflite.yaml in OpenTDF format
- [x] 0g. main.go orchestrator + integration test

## Phase 1: Sealed Policy Bundle — COMPLETE

A single JSON file replaces all config, provisioning scripts, and manual setup. Combined with an SSH key, one file boots a fully configured TDFLite instance.

- [x] Define object contract (Go structs + JSON schema)
- [x] Schema validation (attribute-identity cross-reference)
- [x] Seal/unseal with age library + SSH keys (+ passphrase mode)
- [x] Signature generation/verification (Ed25519, RSA, ECDSA)
- [x] Auto-provisioner: policy file to ConnectRPC calls
- [x] Identity generator: policy identities to idplite format
- [x] Wire into cmd/tdflite (`serve --policy` + `seal` + `rebind` commands)
- [x] Integration tests (6 tests)
- [x] Tamper detection tests (51 subtests — every field modification caught)
- [x] Optional field propagation tests (9 tests)
- [x] Stress tests (11 tests — large bundles, unicode, concurrency, rebind)
- [x] Error path tests (35 tests — cross-mode, wrong keys, validation)
- [x] Policy lifecycle macro test (6 phases, 122 assertions)
- [x] Embedded policy templates (healthcare, finance, defense)
- [x] `tdflite policy seal` command
- [x] `tdflite policy rebind` command

## Phase 2: Zero-Friction Experience — COMPLETE

### `tdflite up` — Interactive Cold Start
- [x] `tdflite up` command — interactive first-run guided setup
- [x] Template selector: healthcare, finance, defense (or custom JSON file)
- [x] Auto-generate Ed25519 SSH keypair if none exists (~/.ssh/id_ed25519)
- [x] Auto-seal, auto-boot — zero manual steps
- [x] Graceful messaging: explain what's happening at each step
- [x] Non-interactive mode: `tdflite up --template healthcare` (scriptable)
- [x] Tests: SSH key gen, template→seal→verify flow, case-insensitive names (14 subtests)

### Embed PostgreSQL Binary
- [x] Bundle Postgres binary via `//go:embed all:pgcache` (~30MB compressed)
- [x] PrepopulateCache writes embedded .txz to library cache dir
- [x] Fallback: if embedded binary present, use it; otherwise download as today
- [x] `scripts/fetch-postgres.sh` — build helper to download .txz for current platform
- [x] Air-gap ready — `bash scripts/fetch-postgres.sh && go build` = zero internet at runtime
- [x] Tests: no-op when empty, skip existing, idempotent calls (7 subtests)

## Deferred

### SQLite Shim — CONSIDERED, DEFERRED

Replacing embedded-postgres with `modernc.org/sqlite` was considered but deferred:
- **Effort:** ~30-45 days (SQL query compatibility, migration rewriting)
- **Benefit:** Instant boot, smaller binary (~35MB total), true single-file
- **Risk:** OpenTDF platform SQL queries are Postgres-specific; compatibility layer is substantial
- **Decision:** Embedded Postgres with `//go:embed` achieves the "zero internet" goal at lower cost. SQLite remains a future optimization if binary size or boot time become priorities.

### In-Memory Mode — CONSIDERED, DEFERRED

Ephemeral mode for testing/CI. Deferred until SQLite shim exists (SQLite `:memory:` is the natural path).

## Enhancements

- [ ] Test with `otdfctl` CLI — live E2E: seal → boot → encrypt → decrypt
- [ ] Add `--log-level` flag
- [ ] Add `--log-format json` flag
- [ ] KAS registry auto-registration (avoid "no rows" warning on startup)

## Code Debt

(None — clean codebase)
