# TDFLite Documentation

## Documentation Tree

| Document | Purpose |
|----------|---------|
| [`../QUICKCONTEXT.md`](../QUICKCONTEXT.md) | 30-second project orientation |
| [`../CLAUDE.md`](../CLAUDE.md) | Agent instructions and project conventions |
| [`../AGENTS.md`](../AGENTS.md) | Agent norms, workstreams, doc maintenance |
| [`../TODO.md`](../TODO.md) | Consolidated task tracking |
| [`../KNOWN_ISSUES.md`](../KNOWN_ISSUES.md) | Active blockers and gotchas |
| [`../config/tdflite.yaml`](../config/tdflite.yaml) | Default configuration (annotated) |
| [`../data/identity.json`](../data/identity.json) | Default identity state for built-in IdP |

## Architecture Overview

TDFLite reimplements the [OpenTDF platform](https://github.com/opentdf/platform) as a single Go binary with no external infrastructure dependencies.

### OpenTDF → TDFLite Mapping

| OpenTDF Component | TDFLite Equivalent | Package |
|-------------------|--------------------|---------|
| Policy Service (PAP) | Policy CRUD handlers | `internal/policy/` |
| Authorization Service (PDP) | Go-native ABAC engine | `internal/authz/` |
| Key Access Server (PEP) | In-process KAS | `internal/kas/` |
| Entity Resolution (PIP) | JWT claims resolver | `internal/entityresolution/` |
| PostgreSQL | In-memory + JSON files | `internal/store/` |
| Keycloak | Built-in OIDC IdP | `internal/authn/idplite/` |
| Caddy (TLS proxy) | Go net/http with optional TLS | `internal/server/` |
| HSM / PKCS#11 | Software crypto (Go stdlib) | `internal/crypto/` |

### Interface-First Design

Every subsystem is defined as a Go interface. This enables:
- **Testing**: Mock any subsystem in tests
- **Gradual upgrade**: Start with lite defaults, swap in production backends
- **Composition**: Mix and match backends (e.g., Postgres store + software crypto)

See `CLAUDE.md` "Architecture Principles" for the full swap table.
