# Quick Context

**Last Updated:** 2026-02-23
**Branch:** main
**Phase:** 2 — Zero-Friction Experience — COMPLETE

## What is TDFLite?

A **thin wrapper binary** around the real [OpenTDF platform](https://github.com/opentdf/platform) that eliminates all infrastructure dependencies. No Docker, no Keycloak, no external Postgres. One file + your SSH key = entire platform.

## Current State

**Phase 0 (Wrap-and-Shim):** COMPLETE
**Phase 1 (Sealed Policy Bundle):** COMPLETE
**Phase 2 (Zero-Friction Experience):** COMPLETE — 315 tests passing

What works today:
- `go build -o tdflite ./cmd/tdflite` → single binary
- `./tdflite up` → interactive cold start wizard (template → keygen → seal → boot)
- `./tdflite up --template healthcare` → non-interactive mode (scriptable)
- `./tdflite policy seal --policy policy.json --ssh-key ~/.ssh/id_ed25519.pub` → sealed bundle
- `./tdflite policy rebind --old-key ... --new-key ...` → SSH key rotation
- `./tdflite serve --policy policy.sealed.json --key ~/.ssh/id_ed25519` → full platform from sealed bundle
- `./tdflite serve --port 9090` → legacy mode (manual config)
- Embedded policy templates: healthcare, finance, defense
- Optional embedded PostgreSQL binary (`scripts/fetch-postgres.sh` → air-gap builds)
- 315 subtests across 9 packages, all passing (race-safe)

## Architecture

```
┌──────────────────────────────────────────────────────┐
│  tdflite up                                          │
│                                                      │
│  1. Check/generate SSH key → ~/.ssh/id_ed25519       │
│  2. Select template        → healthcare/finance/def  │
│  3. Seal with SSH key      → policy.sealed.json      │
│  4. Boot platform          → (same as serve)         │
│                                                      │
│  tdflite serve --policy policy.sealed.json           │
│                                                      │
│  1. Verify signature     → tamper check              │
│  2. Unseal with SSH key  → decrypt KAS + IdP keys    │
│  3. embeddedpg.Start()   → PostgreSQL on :15432      │
│     (PrepopulateCache    → embedded binary if avail)  │
│  4. idplite.Start()      → OIDC IdP on :15433        │
│  5. server.Start()       → Full OpenTDF platform     │
│  6. Auto-provision       → namespace, attrs, mappings │
└──────────────────────────────────────────────────────┘
```

## Key Files

| File | Purpose |
|------|---------|
| `cmd/tdflite/main.go` | CLI: up, serve, policy seal, policy rebind |
| `internal/policybundle/bundle.go` | Bundle types, validation, JSON schema |
| `internal/policybundle/seal.go` | Seal/unseal with age (SSH + passphrase) |
| `internal/policybundle/sign.go` | Signature gen/verify (Ed25519, RSA, ECDSA) |
| `internal/policybundle/identity.go` | Policy identities → idplite format |
| `internal/provision/provision.go` | Auto-provisioner (ConnectRPC calls) |
| `internal/policybundle/templates/` | Embedded templates (healthcare, finance, defense) |
| `internal/idplite/idplite.go` | Built-in OIDC IdP |
| `internal/embeddedpg/embeddedpg.go` | Embedded PostgreSQL wrapper |
| `internal/embeddedpg/cache.go` | Optional //go:embed for PG binary (air-gap) |
| `internal/loader/loader.go` | OpenTDF config YAML generator |
| `internal/keygen/keygen.go` | KAS key pair generation |
| `scripts/fetch-postgres.sh` | Download PG binary for embedding |

## What's Next

1. **Live E2E with otdfctl** — seal → boot → encrypt → decrypt → verify
2. **Logging flags** — `--log-level`, `--log-format json`
3. **KAS registry auto-registration** — avoid "no rows" startup warning
