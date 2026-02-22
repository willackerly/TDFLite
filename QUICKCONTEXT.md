# Quick Context

**Last Updated:** 2026-02-22
**Branch:** main
**Phase:** 2 — Zero-Friction Experience (NEXT)

## What is TDFLite?

A **thin wrapper binary** around the real [OpenTDF platform](https://github.com/opentdf/platform) that eliminates all infrastructure dependencies. No Docker, no Keycloak, no external Postgres. One file + your SSH key = entire platform.

## Current State

**Phase 0 (Wrap-and-Shim):** COMPLETE
**Phase 1 (Sealed Policy Bundle):** COMPLETE — 292 tests passing

What works today:
- `go build -o tdflite ./cmd/tdflite` → single binary
- `./tdflite policy seal --policy policy.json --ssh-key ~/.ssh/id_ed25519.pub` → sealed bundle
- `./tdflite policy rebind --old-key ... --new-key ...` → SSH key rotation
- `./tdflite serve --policy policy.sealed.json --key ~/.ssh/id_ed25519` → full platform from sealed bundle
- `./tdflite serve --port 9090` → legacy mode (manual config)
- Embedded policy templates: healthcare, finance, defense
- 292 subtests across 9 packages, all passing (race-safe)

## Architecture

```
┌──────────────────────────────────────────────────────┐
│  tdflite serve --policy policy.sealed.json           │
│                                                      │
│  1. Verify signature     → tamper check              │
│  2. Unseal with SSH key  → decrypt KAS + IdP keys    │
│  3. embeddedpg.Start()   → PostgreSQL on :15432      │
│  4. idplite.Start()      → OIDC IdP on :15433        │
│  5. server.Start()       → Full OpenTDF platform     │
│  6. Auto-provision       → namespace, attrs, mappings │
└──────────────────────────────────────────────────────┘
```

## Key Files

| File | Purpose |
|------|---------|
| `cmd/tdflite/main.go` | CLI: serve, policy seal, policy rebind |
| `internal/policybundle/bundle.go` | Bundle types, validation, JSON schema |
| `internal/policybundle/seal.go` | Seal/unseal with age (SSH + passphrase) |
| `internal/policybundle/sign.go` | Signature gen/verify (Ed25519, RSA, ECDSA) |
| `internal/policybundle/identity.go` | Policy identities → idplite format |
| `internal/provision/provision.go` | Auto-provisioner (ConnectRPC calls) |
| `internal/policybundle/templates/` | Embedded templates (healthcare, finance, defense) |
| `internal/idplite/idplite.go` | Built-in OIDC IdP |
| `internal/embeddedpg/embeddedpg.go` | Embedded PostgreSQL wrapper |
| `internal/loader/loader.go` | OpenTDF config YAML generator |
| `internal/keygen/keygen.go` | KAS key pair generation |

## What's Next (Phase 2)

1. **`tdflite up`** — Interactive cold start: template selector → keypair gen → seal → boot
2. **Embed Postgres binary** — Bundle via `//go:embed`, eliminate internet dependency
