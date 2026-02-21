# Quick Context

**Last Updated:** 2026-02-21
**Branch:** main
**Phase:** 0 — Wrap-and-Shim

## What is TDFLite?

A **thin wrapper binary** around the real [OpenTDF platform](https://github.com/opentdf/platform) that eliminates all infrastructure dependencies. No Docker, no Keycloak, no external Postgres.

TDFLite starts an **embedded PostgreSQL**, a **built-in OIDC IdP**, and then calls the real `server.Start()` from the OpenTDF platform (imported as a Go module). Full platform functionality, one `go build`, one binary.

## Current State

- **Strategy pivot complete:** Abandoned clean-room reimplementation in favor of wrap-and-shim
- **Architecture plan written:** See `docs/ARCHITECTURE.md` for full details
- **Old scaffolding present:** Previous Go interface stubs still in `internal/` — to be removed in Phase 0a
- **Nothing runs yet** — all implementation is ahead

## What's Next (Phase 0)

1. **0a. Repo restructure** — Remove old scaffolding, rewrite `go.mod` with platform + embedded-postgres deps
2. **0b. idplite** — Build OIDC IdP (~520 lines): discovery, JWKS, token endpoint
3. **0c. Config loader** — Implement `config.Loader` interface for embedded-postgres + idplite injection
4. **0d. main.go** — Orchestrate startup: embedded-postgres → idplite → `server.Start()`
5. **0e. KAS key generation** — Generate RSA + EC key pairs on first run
6. **0f. Default config** — Write `tdflite.yaml` in OpenTDF format
7. **0g. Integration test** — Test with `otdfctl` CLI

Tasks 0b, 0c, 0e can run in parallel. Task 0d depends on all others.

## Key Design Decision

**Wrap, don't rewrite.** The OpenTDF platform has ~40+ DB migrations, sqlc-generated queries, ConnectRPC+gRPC+REST multiplexing, casbin authorization, DPoP support, audit logging, and much more. Reimplementing all of that would take months. Instead, we import the real platform as a Go dependency and inject our own infrastructure (embedded Postgres, built-in IdP) via the platform's exported `StartOptions`.

## Key Files

| File | Purpose |
|------|---------|
| `docs/ARCHITECTURE.md` | Full architecture plan, component details, config spec |
| `data/identity.json` | Default identities (admin + sdk-client) |
| `CLAUDE.md` | Agent instructions |
| `TODO.md` | Task tracking |
