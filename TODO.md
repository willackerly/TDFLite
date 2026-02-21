# TODO

**Last synced:** 2026-02-21

## Phase 0: Wrap-and-Shim (Current)

**Goal:** Full OpenTDF platform running with zero Docker, zero Keycloak, one binary.

See `docs/ARCHITECTURE.md` for full component details and config spec.

### 0a. Repo Restructure (Blocker — must go first)

- [ ] Remove old scaffolding Go code (`internal/store/`, `internal/authn/`, `internal/authz/`, `internal/kas/`, `internal/policy/`, `internal/entityresolution/`, `internal/crypto/`, `internal/server/`, `internal/config/`, `pkg/tdf/`)
- [ ] Rewrite `go.mod` with new module path (`github.com/willackerly/TDFLite`) and dependencies:
  - `github.com/opentdf/platform/service`
  - `github.com/fergusstrange/embedded-postgres`
  - `github.com/lestrrat-go/jwx/v2` (already transitive via platform)
- [ ] Run `go mod tidy` / `go mod download` to verify dependency resolution
- [ ] Create new directory structure: `internal/idplite/`, `internal/loader/`, `internal/embeddedpg/`, `internal/keygen/`
- [ ] Update `.gitignore` for embedded-postgres data dirs

### 0b. idplite — Built-in OIDC IdP (parallel with 0c, 0e)

- [ ] `internal/idplite/idplite.go` — OIDC IdP server (~520 lines)
  - `GET /.well-known/openid-configuration` — discovery document
  - `GET /jwks` — JWK Set (public keys)
  - `POST /token` — client_credentials and password grants
- [ ] Auto-generate RSA signing key on first run (persisted to `data/`)
- [ ] Load identities from `data/identity.json`
- [ ] Tokens contain standard claims: iss, sub, aud, exp, iat, jti, client_id
- [ ] `internal/idplite/idplite_test.go` — unit tests

### 0c. Config Loader (parallel with 0b, 0e)

- [ ] `internal/loader/loader.go` — Implement `config.Loader` interface from `github.com/opentdf/platform/service/pkg/config`
  - Methods: `Get()`, `GetConfigKeys()`, `Load()`, `Watch()`, `Close()`, `Name()`
  - Override: `db.host`, `db.port`, `db.password`, `db.sslmode` → embedded postgres
  - Override: `server.auth.issuer` → idplite URL
  - Override: `services.entityresolution.mode` → `claims`
- [ ] `internal/loader/loader_test.go` — unit tests

### 0d. Embedded Postgres Wrapper (parallel with 0b, 0c)

- [ ] `internal/embeddedpg/embeddedpg.go` — Lifecycle wrapper
  - Start embedded-postgres with V16 (native ARM64)
  - Port 15432, database `opentdf`, data in `data/postgres/`
  - Cache Postgres binary in `data/cache/`
  - Graceful shutdown
- [ ] `internal/embeddedpg/embeddedpg_test.go` — unit tests

### 0e. KAS Key Generation (parallel with 0b, 0c)

- [ ] `internal/keygen/keygen.go` — Generate on first run:
  - RSA-2048 key pair → `data/kas-private.pem` + `data/kas-cert.pem`
  - EC secp256r1 key pair → `data/kas-ec-private.pem` + `data/kas-ec-cert.pem`
  - Skip generation if files already exist

### 0f. Default Config

- [ ] `config/tdflite.yaml` — Rewrite in OpenTDF format (see ARCHITECTURE.md for spec)
  - `dev_mode: true`, `mode: [all]`
  - DB config pointing at embedded postgres
  - Auth config pointing at idplite
  - Crypto provider with KAS key paths
  - Entity resolution in claims mode

### 0g. main.go + Integration

- [ ] `cmd/tdflite/main.go` — Rewrite from scratch:
  1. Parse flags / load config
  2. Generate KAS keys if needed
  3. Start embedded-postgres (wait for ready)
  4. Start idplite OIDC IdP (wait for ready)
  5. Build custom config.Loader
  6. Call `server.Start()` with `WithAdditionalConfigLoader()` + `WithConfigLoaderOrder()`
  7. Handle graceful shutdown (reverse order)
- [ ] Integration test: start TDFLite, hit health endpoint, create namespace via API
- [ ] Test with `otdfctl` CLI if available

## Phase 1: SQLite Shim (Future)

- [ ] Replace embedded-postgres with `modernc.org/sqlite`
- [ ] Implement pgx-to-SQLite bridge or rewrite DB layer
- [ ] True single binary — no Postgres download on first run
- [ ] Estimated effort: ~30-45 days

## Phase 2: In-Memory Mode (Future)

- [ ] Add ephemeral in-memory mode for testing/demos
- [ ] No persistence, fresh state on every start
- [ ] Useful for CI/CD pipelines and SDK tests

## Code Debt

(None yet — fresh start with wrap-and-shim)
