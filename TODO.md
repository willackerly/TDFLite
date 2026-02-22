# TODO

**Last synced:** 2026-02-22

## Phase 0: Wrap-and-Shim — COMPLETE

All tasks done and verified end-to-end. Binary builds, all services start, health endpoint responds, tokens issue.

- [x] 0a. Repo restructure — removed old scaffolding, rewrote go.mod
- [x] 0b. idplite — built-in OIDC IdP (discovery, JWKS, token endpoint)
- [x] 0c. Config loader — YAML generator in OpenTDF format
- [x] 0d. Embedded PostgreSQL wrapper — V16, native ARM64
- [x] 0e. KAS key generation — RSA-2048 + EC P-256, idempotent
- [x] 0f. Default config — tdflite.yaml in OpenTDF format
- [x] 0g. main.go orchestrator + integration test

## Phase 1: Sealed Policy Bundle (IN PROGRESS)

A single JSON file replaces all config, provisioning scripts, and manual setup. Combined with an SSH key, one file boots a fully configured TDFLite instance.

- [x] Define object contract (Go structs + JSON schema)
- [x] Schema validation (attribute-identity cross-reference)
- [x] Seal/unseal with age library + SSH keys (+ passphrase mode)
- [x] Signature generation/verification (Ed25519, RSA, ECDSA)
- [x] Auto-provisioner: policy file to ConnectRPC calls
- [x] Identity generator: policy identities to idplite format
- [x] Wire into cmd/tdflite (`serve --policy` + `seal` + `rebind` commands)
- [x] Integration tests: seal, sign, verify, unseal, provision (6 tests)
- [ ] Live E2E test: seal → boot → encrypt → decrypt with otdfctl

## Phase 2: SQLite Shim (Future)

- [ ] Replace embedded-postgres with `modernc.org/sqlite`
- [ ] Implement pgx-to-SQLite bridge or rewrite DB layer
- [ ] True single binary — no Postgres download on first run
- [ ] Estimated effort: ~30-45 days

## Phase 3: In-Memory Mode (Future)

- [ ] Add ephemeral in-memory mode for testing/demos
- [ ] No persistence, fresh state on every start
- [ ] Useful for CI/CD pipelines and SDK tests

## Enhancements

- [ ] Test with `otdfctl` CLI — verify full SDK compatibility
- [ ] Add `tdflite init` command for first-run setup
- [ ] Add `--log-level` flag
- [ ] Add `--log-format json` flag
- [ ] Consider making default port configurable via env var
- [ ] KAS registry auto-registration (avoid "no rows" warning on startup)
- [x] `tdflite policy seal` command
- [x] `tdflite policy rebind` command

## Code Debt

(None — clean codebase)
