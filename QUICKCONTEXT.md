# Quick Context

**Last Updated:** 2026-02-21
**Branch:** main
**Phase:** 0 — Wrap-and-Shim (COMPLETE)

## What is TDFLite?

A **thin wrapper binary** around the real [OpenTDF platform](https://github.com/opentdf/platform) that eliminates all infrastructure dependencies. No Docker, no Keycloak, no external Postgres.

TDFLite starts an **embedded PostgreSQL**, a **built-in OIDC IdP**, and then calls the real `server.Start()` from the OpenTDF platform (imported as a Go module). Full platform functionality, one `go build`, one binary.

## Current State

Phase 0 is **complete and verified end-to-end:**
- `go build -o tdflite ./cmd/tdflite` → single binary
- `./tdflite serve --port 9090` starts everything:
  - Embedded PostgreSQL on :15432
  - idplite OIDC IdP on :15433
  - OpenTDF platform with all 17 services on :9090
  - 39 database migrations auto-applied
- `/healthz` returns `{"status":"SERVING"}`
- idplite issues valid JWTs via `client_credentials` grant
- All 33+ unit tests pass

## Architecture

```
┌──────────────────────────────────────────────────────┐
│  tdflite serve                                       │
│                                                      │
│  1. keygen.EnsureKeys()     → RSA + EC key pairs     │
│  2. embeddedpg.Start()      → PostgreSQL on :15432   │
│  3. idplite.Start()         → OIDC IdP on :15433     │
│  4. loader.WriteConfigFile()→ opentdf.yaml generated  │
│  5. server.Start()          → Full OpenTDF platform   │
└──────────────────────────────────────────────────────┘
```

## Key Files

| File | Purpose |
|------|---------|
| `cmd/tdflite/main.go` | Orchestrator — startup sequence |
| `internal/idplite/idplite.go` | Built-in OIDC IdP (544 lines) |
| `internal/embeddedpg/embeddedpg.go` | Embedded PostgreSQL wrapper |
| `internal/loader/loader.go` | OpenTDF config YAML generator |
| `internal/keygen/keygen.go` | KAS RSA + EC key pair generation |
| `data/identity.json` | Default identities (admin + sdk-client) |
| `CLAUDE.md` | Agent instructions |
| `TODO.md` | Task tracking |

## What's Next (Phase 1)

- Replace embedded-postgres with `modernc.org/sqlite` for true single-binary
- Or proceed to Phase 2 (in-memory mode for testing)
- Or add `otdfctl` integration tests
