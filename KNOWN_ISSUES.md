# Known Issues

**Last Updated:** 2026-02-21

## Active Issues

### Port 8080 Conflict
If port 8080 is in use (e.g., Docker), use `--port 9090` or another free port. The platform will fail with `bind: address already in use` otherwise.

### KAS Registry "No Rows" Warning
On startup, the KAS registry service logs `ERROR: no rows in result set (SQLSTATE 20000)`. This is non-fatal — it just means no KAS servers are registered in the database yet. The platform handles this gracefully and continues.

## Gotchas

### Embedded Postgres — Use V16, Not Default
`fergusstrange/embedded-postgres` defaults to V18, which requires Rosetta 2 on macOS ARM64. **Always specify `embeddedpostgres.V16`** for native ARM64 support.

### idplite Must Start Before server.Start()
The OpenTDF platform does OIDC discovery (`/.well-known/openid-configuration`) during startup. If idplite isn't serving yet, `server.Start()` will fail with a connection refused error. The orchestrator handles this correctly.

### Entity Resolution Mode
Set `services.entityresolution.mode: claims` in config. Without this, the platform will try to connect to Keycloak for entity resolution and fail.

### Platform SQL Is Postgres-Specific
The OpenTDF platform's SQL layer uses JSONB, PL/pgSQL triggers, array types, `FILTER` aggregates, table inheritance, and GIN indexes. These are not portable to SQLite without significant effort (~30-45 days). This is why Phase 0 uses embedded Postgres.

### Data Directories
Embedded Postgres creates `data/postgres/` and `data/cache/` at runtime. These are in `.gitignore` and should not be committed. The Postgres binary (~25MB) is downloaded on first run and cached.

### First Run is Slow
First `./tdflite serve` downloads the PostgreSQL binary (~25MB), initializes the database cluster, and runs 39 migrations. Subsequent starts are fast (<2 seconds to full readiness).

## Resolved Issues

### Old Scaffolding Removed
Previous clean-room reimplementation code was removed in Phase 0a.

### Go Module Path Fixed
Module path corrected from `github.com/willnorris/tdflite` to `github.com/willackerly/TDFLite`.
