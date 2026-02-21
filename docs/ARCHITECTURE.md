# TDFLite Architecture — Fork-and-Shim Strategy

**Created:** 2026-02-21
**Status:** Approved, ready for implementation

## Strategy: Wrap OpenTDF, Don't Rewrite It

After deep analysis of the OpenTDF platform codebase (`github.com/opentdf/platform`), the original clean-room reimplementation approach was abandoned in favor of a **wrap-and-shim** strategy. The OpenTDF platform has ~40+ DB migrations, sqlc-generated queries, ConnectRPC+gRPC+REST multiplexing, casbin authorization, DPoP support, audit logging, and much more. Reimplementing all of that would take months.

Instead, TDFLite is a **thin wrapper binary** that:
1. Starts an **embedded PostgreSQL** instance (no Docker)
2. Starts a **built-in OIDC Identity Provider** (no Keycloak)
3. Calls `server.Start()` from the real OpenTDF platform (imported as a Go module dependency)
4. Injects config pointing at the embedded Postgres + built-in IdP

**Result:** Full OpenTDF platform functionality. Zero Docker. Zero external infrastructure. One `go build`, one binary.

## Key Research Findings

### The Platform Is Extensible Without Forking

`server.Start()` in `github.com/opentdf/platform/service/pkg/server` accepts `StartOptions`:

| Hook | What It Does |
|------|-------------|
| `WithAdditionalConfigLoader()` | Inject custom config (DB host/port, auth issuer) |
| `WithConfigLoaderOrder()` | Make our loader highest priority |
| `WithServices()` | Register extra services (our IdP) |
| `WithCoreServices()` | Register core-mode services |
| `WithBuiltinAuthZPolicy()` | Override casbin policy |
| `WithConnectInterceptors()` | Add custom interceptors |
| `WithTrustKeyManagerCtxFactories()` | Provide crypto keys programmatically |

### Auth Layer Is Generic OIDC

The platform's auth (`service/internal/auth/authn.go`) does standard OIDC:
- Fetches `/.well-known/openid-configuration`
- Gets JWKS from `jwks_uri`
- Validates JWTs with `lestrrat-go/jwx/v2`
- No Keycloak-specific code in the auth path

**Any OIDC-compliant IdP works.** We just need to serve discovery + JWKS + token endpoints.

### Entity Resolution Without Keycloak

Set `services.entityresolution.mode: claims` in config. The claims-based entity resolver has zero external dependencies — it just reads JWT claims.

### Database Is Deeply Postgres-Coupled

The SQL layer is ~60% Postgres-specific (JSONB, PL/pgSQL triggers, array types, `FILTER` aggregates, table inheritance, GIN indexes). Porting to SQLite would be ~30-45 days. Embedded Postgres is ~1-2 days.

## Architecture Diagram

```
┌──────────────────────────────────────────────┐
│              tdflite binary (Go)             │
│                                              │
│  cmd/tdflite/main.go                         │
│    1. Start embedded-postgres (:15432)       │
│    2. Start idplite OIDC IdP (:15433)        │
│    3. Create custom config.Loader            │
│    4. Call server.Start() with options        │
│                                              │
│  internal/idplite/     (~520 lines)          │
│    OIDC discovery, JWKS, token endpoint      │
│    Uses lestrrat-go/jwx for JWT signing      │
│    Loads identities from data/identity.json  │
│                                              │
│  internal/config/                            │
│    Custom config.Loader implementing         │
│    github.com/opentdf/platform/              │
│      service/pkg/config.Loader interface     │
│                                              │
│  Go module dependencies:                     │
│    github.com/opentdf/platform/service       │
│    github.com/fergusstrange/embedded-postgres │
│    github.com/lestrrat-go/jwx/v2            │
└──────────────────────────────────────────────┘
         │                    │
         ▼                    ▼
   ┌───────────┐       ┌───────────┐
   │ embedded  │       │  idplite  │
   │ postgres  │       │   OIDC    │
   │  :15432   │       │  :15433   │
   └───────────┘       └───────────┘
```

## Phased Roadmap

### Phase 0: Wrap-and-Shim (Current)

**Goal:** Full OpenTDF platform running with zero Docker, zero Keycloak.

| Task | Description | Parallelizable? |
|------|-------------|-----------------|
| **0a. Repo restructure** | Remove old scaffolding, update go.mod to depend on platform + embedded-postgres | Blocker |
| **0b. idplite** | Build OIDC IdP (~520 lines): discovery, JWKS, token endpoint using lestrrat-go/jwx | Yes (parallel with 0c) |
| **0c. Config loader** | Implement `config.Loader` interface for embedded-postgres + idplite injection | Yes (parallel with 0b) |
| **0d. main.go** | Orchestrate startup: embedded-postgres -> idplite -> server.Start() | After 0a-c |
| **0e. KAS key generation** | Generate RSA + EC key pairs on first run, write to data/ | Yes (parallel with 0b/0c) |
| **0f. Default config** | Write tdflite.yaml with all OpenTDF config fields | After 0c |
| **0g. Integration test** | Test with otdfctl CLI | After 0d |

### Phase 1: SQLite Shim (Future)

Replace embedded-postgres with `modernc.org/sqlite`. Requires rewriting the DB layer or implementing a pgx-to-SQLite bridge. True single binary. ~30-45 days effort.

### Phase 2: In-Memory Mode (Future)

Add ephemeral in-memory mode for testing/demos. Our original interface-first store design may be useful here.

## Component Details

### Embedded PostgreSQL

**Library:** `github.com/fergusstrange/embedded-postgres` (MIT license, v1.33.0)

- Downloads real Postgres binary (~25MB) on first run, caches in `data/cache/`
- **Use Postgres V16** (not default V18) for native macOS ARM64 without Rosetta 2
- Data persists in `data/postgres/` between restarts
- Connects via standard `postgres://` URL compatible with pgx/v5
- All existing OpenTDF migrations run unchanged

```go
cfg := embeddedpostgres.DefaultConfig().
    Version(embeddedpostgres.V16).
    Port(15432).
    Database("opentdf").
    Username("postgres").
    Password("changeme").
    DataPath("./data/postgres").
    CachePath("./data/cache").
    StartTimeout(30 * time.Second)
```

### Built-in OIDC IdP (idplite)

**~520 lines of Go using `lestrrat-go/jwx/v2`** (same JWT library OpenTDF validates with).

Endpoints:
- `GET /.well-known/openid-configuration` — static JSON with issuer, jwks_uri, token_endpoint
- `GET /jwks` — public key set as JWK Set JSON
- `POST /token` — client_credentials and password grants

Features:
- RSA or EC signing keys (auto-generated on first run, persisted to `data/`)
- Identities loaded from `data/identity.json`
- Tokens contain standard claims (iss, sub, aud, exp, iat, jti, client_id)
- Zero new dependencies (lestrrat-go/jwx is already transitive via the platform)

**Critical timing:** idplite MUST be serving before `server.Start()` is called, because OpenTDF does OIDC discovery during startup.

### Custom Config Loader

Implements `github.com/opentdf/platform/service/pkg/config.Loader`:

```go
type Loader interface {
    Get(key string) (any, error)
    GetConfigKeys() ([]string, error)
    Load(mostRecentConfig Config) error
    Watch(ctx context.Context, cfg *Config, onChange func(context.Context) error) error
    Close() error
    Name() string
}
```

Overrides:
- `db.host` → `localhost`
- `db.port` → embedded postgres port
- `db.password` → embedded postgres password
- `db.sslmode` → `disable`
- `server.auth.issuer` → idplite issuer URL
- `services.entityresolution.mode` → `claims`

## Sub-Agent Parallelization Plan

For maximum speed, the following tasks can run in parallel:

```
                    ┌─ Agent A: idplite implementation
                    │   - OIDC discovery endpoint
                    │   - JWKS endpoint
                    │   - Token endpoint (client_credentials + password)
                    │   - Identity loading from JSON
                    │   - Tests
                    │
 0a. Repo setup ────┼─ Agent B: Config loader + embedded-postgres integration
 (sequential,       │   - Implement config.Loader interface
  must go first)    │   - Embedded-postgres startup/shutdown
                    │   - Connection URL generation
                    │   - Tests
                    │
                    ├─ Agent C: KAS key generation + default config
                    │   - Generate RSA-2048 + EC secp256r1 key pairs
                    │   - Write PEM files to data/
                    │   - Create tdflite.yaml with all required fields
                    │   - Casbin policy for default roles
                    │
                    └─ Agent D: main.go + integration test
                        - Orchestrate startup sequence
                        - Wire everything together
                        - Test with otdfctl
                        (depends on A, B, C completing)
```

## Files to Keep from Current Repo

| File | Action |
|------|--------|
| `CLAUDE.md` | Update with new structure |
| `QUICKCONTEXT.md` | Update with new strategy |
| `TODO.md` | Rewrite with new phases |
| `KNOWN_ISSUES.md` | Update |
| `AGENTS.md` | Update with new structure |
| `docs/ARCHITECTURE.md` | This file (new) |
| `data/identity.json` | Keep as-is |
| `.gitignore` | Create |

## Files to Remove

All old scaffolding Go code:
- `internal/store/` (entire tree) — replaced by platform's DB layer
- `internal/authn/authn.go` — replaced by platform's auth
- `internal/authz/` — replaced by platform's casbin
- `internal/kas/` — replaced by platform's KAS
- `internal/policy/` — replaced by platform's policy service
- `internal/entityresolution/` — replaced by platform's ERS
- `internal/crypto/` — replaced by platform's security package
- `internal/server/` — replaced by platform's server
- `internal/config/config.go` — replaced by custom loader
- `pkg/tdf/` — replaced by platform's SDK
- `cmd/tdflite/main.go` — rewrite from scratch
- `config/tdflite.yaml` — rewrite for OpenTDF format
- `go.mod` / `go.sum` — rewrite with new deps

## Files to Create

| File | Purpose |
|------|---------|
| `cmd/tdflite/main.go` | New main: embedded-postgres -> idplite -> server.Start() |
| `internal/idplite/idplite.go` | OIDC IdP: discovery, JWKS, token |
| `internal/idplite/idplite_test.go` | Tests for idplite |
| `internal/loader/loader.go` | Custom config.Loader for TDFLite |
| `internal/loader/loader_test.go` | Tests for loader |
| `internal/embeddedpg/embeddedpg.go` | Embedded-postgres wrapper with lifecycle |
| `internal/embeddedpg/embeddedpg_test.go` | Tests |
| `internal/keygen/keygen.go` | KAS key pair generation on first run |
| `config/tdflite.yaml` | Default config in OpenTDF format |
| `.gitignore` | Binary, data/postgres/, data/cache/, IDE files |

## Minimum Viable Config (OpenTDF Format)

```yaml
dev_mode: true
mode:
  - all

db:
  host: localhost
  port: 15432
  database: opentdf
  user: postgres
  password: changeme
  sslmode: disable
  schema: opentdf
  runMigrations: true

server:
  port: 8080
  auth:
    enabled: true
    enforceDPoP: false
    audience: "http://localhost:8080"
    issuer: "http://localhost:15433"
    policy:
      client_id_claim: "client_id"
      username_claim: "preferred_username"
      groups_claim: "realm_access.roles"
  tls:
    enabled: false
  cors:
    enabled: true
    allowedorigins:
      - "*"
  grpc:
    reflectionEnabled: true
  cryptoProvider:
    type: standard
    standard:
      keys:
        - kid: r1
          alg: rsa:2048
          private: data/kas-private.pem
          cert: data/kas-cert.pem
        - kid: e1
          alg: ec:secp256r1
          private: data/kas-ec-private.pem
          cert: data/kas-ec-cert.pem

services:
  entityresolution:
    mode: claims
  policy:
    list_request_limit_max: 2500
    list_request_limit_default: 1000
```

## Research References

The following research was conducted on 2026-02-21 and informed this architecture:

1. **Embedded Postgres**: `fergusstrange/embedded-postgres` v1.33.0 — MIT, downloads real Postgres, ~2-5s startup, V16 for native ARM64
2. **OIDC IdP Options**: Evaluated Ory Fosite (87 deps), dexidp/dex (125+ deps, no client_credentials), zitadel/oidc (32 deps), custom build (~1 dep). Custom wins.
3. **SQL Compatibility**: Platform is ~60% Postgres-specific. SQLite port ~30-45 days. Embedded Postgres ~1-2 days.
4. **server.Start() Extensibility**: Fully supports external wrapping via StartOptions. No fork needed for Phase 0.
5. **Entity Resolution**: `mode: claims` eliminates all Keycloak dependency. Zero external deps.

Full research outputs are preserved in the conversation history and can be regenerated by analyzing `/Users/will/dev/platform/`.
