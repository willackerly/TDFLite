# TODO

**Last synced:** 2026-02-21

## Phase 0: Wrap-and-Shim — COMPLETE

All tasks done and verified end-to-end. Binary builds, all services start, health endpoint responds, tokens issue.

- [x] 0a. Repo restructure — removed old scaffolding, rewrote go.mod
- [x] 0b. idplite — built-in OIDC IdP (discovery, JWKS, token endpoint)
- [x] 0c. Config loader — YAML generator in OpenTDF format
- [x] 0d. Embedded PostgreSQL wrapper — V16, native ARM64
- [x] 0e. KAS key generation — RSA-2048 + EC P-256, idempotent
- [x] 0f. Default config — tdflite.yaml in OpenTDF format
- [x] 0g. main.go orchestrator + integration test

## Phase 1: SQLite Shim (Future)

- [ ] Replace embedded-postgres with `modernc.org/sqlite`
- [ ] Implement pgx-to-SQLite bridge or rewrite DB layer
- [ ] True single binary — no Postgres download on first run
- [ ] Estimated effort: ~30-45 days

## Phase 2: In-Memory Mode (Future)

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

## Code Debt

(None — clean codebase)
