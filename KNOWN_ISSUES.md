# Known Issues

**Last Updated:** 2026-02-21

## Active Issues

### Old Scaffolding Still Present
The repo contains old Go code from the abandoned clean-room reimplementation (`internal/store/`, `internal/authn/`, etc.). This code is not used and will be removed in Phase 0a (repo restructure). **Do not build on this code.**

### Go Module Path Wrong
The module is `github.com/willnorris/tdflite` (wrong username). Will be fixed to `github.com/willackerly/TDFLite` during repo restructure.

## Gotchas

### Embedded Postgres — Use V16, Not Default
`fergusstrange/embedded-postgres` defaults to V18, which requires Rosetta 2 on macOS ARM64. **Always specify `embeddedpostgres.V16`** for native ARM64 support.

### idplite Must Start Before server.Start()
The OpenTDF platform does OIDC discovery (`/.well-known/openid-configuration`) during startup. If idplite isn't serving yet, `server.Start()` will fail with a connection refused error. Use a readiness check before proceeding.

### Entity Resolution Mode
Set `services.entityresolution.mode: claims` in config. Without this, the platform will try to connect to Keycloak for entity resolution and fail.

### Platform SQL Is Postgres-Specific
The OpenTDF platform's SQL layer uses JSONB, PL/pgSQL triggers, array types, `FILTER` aggregates, table inheritance, and GIN indexes. These are not portable to SQLite without significant effort (~30-45 days). This is why Phase 0 uses embedded Postgres.

### Data Directories
Embedded Postgres will create `data/postgres/` and `data/cache/` at runtime. These are in `.gitignore` and should not be committed. The Postgres binary (~25MB) is downloaded on first run and cached.
