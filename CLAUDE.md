# CLAUDE.md

Project instructions for Claude Code. These override defaults—follow them exactly.

## Project: TDFLite

Lightweight, single-binary reimplementation of the OpenTDF platform in pure Go. No Docker, no Postgres, no Keycloak. All services (Policy, Authorization, KAS, Entity Resolution, OIDC IdP) run in one daemon with pluggable backends behind clean Go interfaces.

## Cold Start (New Agent?)

**Read in order (5 min total):**
1. `QUICKCONTEXT.md` → 30-second orientation, current state
2. `KNOWN_ISSUES.md` → blockers, gotchas, common errors
3. `TODO.md` → what needs doing

**Then deep dive:**
4. `AGENTS.md` → norms, workstreams, doc maintenance policy
5. `docs/README.md` → full documentation tree

## Commands

```bash
go build ./...                    # build all packages
go build -o tdflite ./cmd/tdflite # build the binary
go test ./...                     # run all tests
go test -race ./...               # tests with race detector
go vet ./...                      # static analysis
gofmt -s -w .                     # format code
golangci-lint run                 # lint (if installed)
./tdflite serve                   # run the daemon
./tdflite serve --config config/tdflite.yaml  # run with explicit config
```

## Structure

- `cmd/tdflite/` — Main binary entry point
- `internal/server/` — HTTP/gRPC server wiring, router, middleware
- `internal/config/` — Configuration loading (YAML)
- `internal/store/` — **Storage interface** + implementations (memory, jsonfile)
- `internal/authn/` — **Authentication interface** + lightweight OIDC IdP
- `internal/authz/` — **Authorization interface** + ABAC engine
- `internal/kas/` — **Key Access Server** interface + handlers
- `internal/policy/` — **Policy service** interface + handlers
- `internal/entityresolution/` — **Entity resolution** interface + JWT resolver
- `internal/crypto/` — **Crypto operations** interface + software impl
- `pkg/tdf/` — TDF and NanoTDF format library (public API)
- `config/` — Default configuration files (YAML)
- `data/` — Default identity/state files (JSON)
- `docs/` — Documentation

## Coding Style

Go idiomatic. `gofmt` defaults. No framework dependencies—stdlib `net/http` and `crypto/*` where possible.

**Interface-first design** is the core architectural principle:
- Every major subsystem is defined as a Go interface in its package root
- Lightweight implementations live in sub-packages (e.g., `store/memory/`, `store/jsonfile/`)
- Heavier implementations (Postgres, Keycloak, HSM) can be swapped in later without changing callers
- Constructors return the interface type, not the concrete type
- Keep interfaces small and focused (Interface Segregation Principle)

Name files after their primary export. Keep changes minimal—don't over-engineer.

Use `context.Context` as first parameter on all interface methods.
Use `error` returns, not panics. Wrap errors with `fmt.Errorf("context: %w", err)`.

## Testing

Co-locate unit tests beside code (`foo_test.go` next to `foo.go`).
Integration tests in `tests/` directory.
Test against interfaces, not concrete implementations.
Use table-driven tests. Use `testify` only if already a dependency.

---

## Allowed Commands

The following command patterns are pre-approved for autonomous execution:

### Go Build & Test
- `go build ./...`, `go build -o tdflite ./cmd/tdflite`
- `go test ./...`, `go test -race ./...`, `go test -v ./...`
- `go test -run <pattern> ./...`
- `go vet ./...`, `go mod tidy`, `go mod download`
- `go generate ./...`
- `gofmt -s -w .`, `goimports -w .`
- `golangci-lint run`

### Git Operations
- `git status`, `git diff`, `git log`, `git show`
- `git add`, `git commit`, `git push`, `git pull`
- `git checkout`, `git branch`, `git fetch`
- `git stash`, `git reset`, `git restore`
- `git cherry-pick`, `git merge`, `git rebase`
- `git rm`, `git mv`, `git ls-tree`, `git show-ref`
- `git worktree`, `git remote`

### File & System Utilities
- `ls`, `tree`, `find`, `cat`, `head`, `tail`
- `echo`, `tee`, `stat`, `chmod`
- `curl`, `jq`

### Scripts
- `bash scripts/*.sh`

### Diagnostics
- Any script under `scripts/diagnostics/`
- Temp scripts in `/tmp/`

## Web Fetch Domains

Pre-approved for fetching:
- `opentdf.io`
- `github.com/opentdf`
- `pkg.go.dev`
- `golang.org`

## Agent Autonomy

**This project grants MAXIMUM autonomy.** Act decisively. Ship code. Don't ask permission for routine work.

### DO WITHOUT ASKING

1. **All coding tasks** — Write, edit, refactor, delete code freely
2. **All testing** — Run, write, fix, skip tests as needed
3. **All builds** — Build, rebuild, clean as needed
4. **All git operations** — Add, commit, push, branch, merge, rebase
5. **All dependency changes** — Add, remove, upgrade packages
6. **All documentation** — Create, update, reorganize, archive docs
7. **All file operations** — Create, move, rename, delete files
8. **Bug fixes** — Fix bugs immediately without discussion
9. **Refactoring** — Improve code quality, reduce duplication
10. **Test fixes** — Update broken tests, add missing coverage
11. **Config changes** — Update configs, env vars, build settings
12. **Minor features** — Small enhancements that follow existing patterns
13. **Error handling** — Add/improve error handling and logging
14. **Performance fixes** — Optimize slow code paths

### ASK ONLY FOR

**Fundamental architectural decisions** that would be hard to reverse:

1. **New major dependencies** — Adding a framework or large library
2. **Interface changes** — Modifying published Go interfaces (breaking change)
3. **Security model changes** — Altering encryption, auth, or key management approach
4. **New subsystems** — Creating entirely new internal packages
5. **Protocol changes** — Modifying API surface, wire formats
6. **Breaking changes** — Changes that break existing callers

**When in doubt:** If a change follows existing patterns and is reversible, just do it. If it establishes a new pattern or is hard to undo, enter plan mode.

### Force Operations (require explicit user request)

- `git push --force` to shared branches
- `git reset --hard` on commits others might have
- Deleting production data or databases
- Modifying secrets/credentials in production

## Architecture Principles

### 1. Interface-First, Swap-Ready

Every subsystem has a clean Go interface. The "lite" implementations (in-memory, JSON files, software crypto) are the defaults. Heavier implementations can be added:

| Subsystem | Lite Default | Swap-In Options |
|-----------|-------------|-----------------|
| **Store** | In-memory + JSON file persistence | PostgreSQL, SQLite, etcd |
| **AuthN** | Built-in lightweight OIDC IdP | Keycloak, Auth0, Okta |
| **AuthZ** | Go-native ABAC engine | OPA/Rego, Casbin, Cedar |
| **Crypto** | `crypto/rsa` + `crypto/ecdsa` (software) | PKCS#11 HSM, AWS KMS, Vault Transit |
| **Entity Resolution** | JWT claims extraction | LDAP, PostgreSQL, SCIM |
| **KAS** | In-process key management | Remote KAS, split-key federation |

### 2. Single Binary, Zero Infrastructure

`go build` produces one binary. `./tdflite serve` starts everything. No Docker, no Postgres, no Keycloak, no Caddy.

### 3. OpenTDF Protocol Compatible

Preserve the same API surface as OpenTDF platform so existing SDKs and `otdfctl` work against TDFLite. gRPC + ConnectRPC + REST/JSON gateway.

### 4. Configuration via YAML, State via JSON

- `config/tdflite.yaml` — daemon configuration
- `data/` — runtime state persisted as JSON files (identity, policy, keys)

## Active Workstreams

- **P0** — Core scaffolding and interface definitions (current)
- **P1** — Policy service + in-memory store
- **P2** — KAS with software crypto
- **P3** — Built-in OIDC IdP
- **P4** — Authorization engine
- **P5** — TDF encrypt/decrypt end-to-end

## Environment Variables

```bash
TDFLITE_CONFIG=./config/tdflite.yaml   # config file path
TDFLITE_PORT=8080                       # server port
TDFLITE_DATA_DIR=./data                 # state persistence directory
TDFLITE_LOG_LEVEL=info                  # debug, info, warn, error
```

---

## TODO Tracking Methodology (MANDATORY)

**This is a hard requirement. Follow exactly.**

### The Two-Tag System

| Tag | Meaning | Action Required |
|-----|---------|-----------------|
| `TODO:` | Untracked work item | Must be tracked before commit |
| `TRACKED-TASK:` | Already in TODO.md/docs | Periodically verify still documented |

### Workflow

**When you add a TODO in code:**
```go
// TODO: Handle edge case for X
```

**Before committing, you MUST either:**
1. Fix it immediately (remove the TODO), OR
2. Track it in `TODO.md` and convert to:
```go
// TRACKED-TASK: Handle edge case for X - see TODO.md "Code Debt"
```

### Pre-Commit Checklist

**Run before every commit:**
```bash
# Find untracked TODOs (should be 0 before commit)
grep -rn "TODO:" --include="*.go" internal/ pkg/ cmd/

# Find tracked tasks (audit these periodically)
grep -rn "TRACKED-TASK:" --include="*.go" internal/ pkg/ cmd/
```

**If untracked TODOs exist, you must:**
1. Add each to `TODO.md` under appropriate section
2. Convert `TODO:` → `TRACKED-TASK:` in source
3. Re-run check to confirm zero untracked TODOs
