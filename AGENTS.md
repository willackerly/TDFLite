# Repository Guidelines

## Read Before Coding

**Quick start (new agent):**
1. `QUICKCONTEXT.md` → 30-second orientation, current state of the world
2. `KNOWN_ISSUES.md` → active blockers, gotchas, common errors
3. `TODO.md` → consolidated task tracking

**Full context:**
4. `docs/ARCHITECTURE.md` → full architecture plan, component specs, config format
5. `AGENTS.md` (this file) → norms
6. `CLAUDE.md` → project instructions

## Agent Autonomy

**Maximum autonomy granted.** Act decisively. Ship code. Don't ask permission for routine work.

### Full Authority (no approval needed)
- Write, edit, refactor, delete code
- Run, write, fix tests
- Git: commit, push, branch, merge, rebase
- Add/remove/upgrade dependencies
- Create, update, reorganize, archive documentation
- Fix bugs, improve error handling, optimize performance
- Implement features that follow existing patterns

### Requires Discussion (enter plan mode)
Only **fundamental architectural decisions** that are hard to reverse:
- New major dependencies (e.g., framework changes)
- Interface changes (modifying published Go interfaces — these are the project's contracts)
- Security model changes (encryption, auth, key management)
- Creating new internal subsystem packages beyond the planned structure
- Protocol changes (API surface, wire formats)
- Breaking changes affecting existing callers

### Never Without Explicit Request
- `git push --force` to shared branches
- `git reset --hard` on commits others have
- Deleting production data
- Modifying production secrets

**Rule of thumb:** If it follows existing patterns and is reversible → just do it. If it establishes new patterns or is hard to undo → plan mode.

---

## Project Structure (Wrap-and-Shim)

TDFLite is a Go module (`github.com/willackerly/TDFLite`) that wraps the real OpenTDF platform.

**Key principle: Wrap, don't rewrite.** Import the OpenTDF platform as a Go dependency. Inject embedded Postgres + built-in OIDC IdP via the platform's exported `StartOptions`. Touch zero platform source code.

### New Structure (Phase 0 target)

| Package | Responsibility |
|---------|---------------|
| `cmd/tdflite/` | Binary entry point — orchestrates startup sequence |
| `internal/idplite/` | Built-in OIDC IdP (discovery, JWKS, token endpoint) |
| `internal/loader/` | Custom `config.Loader` for injecting our infrastructure |
| `internal/embeddedpg/` | Embedded PostgreSQL lifecycle wrapper |
| `internal/keygen/` | KAS key pair generation (RSA + EC) on first run |
| `config/` | Default `tdflite.yaml` in OpenTDF config format |
| `data/` | Runtime state: identity JSON, generated keys, Postgres data |

### Key Dependencies

| Dependency | Purpose |
|-----------|---------|
| `github.com/opentdf/platform/service` | The real OpenTDF platform (imported, not forked) |
| `github.com/fergusstrange/embedded-postgres` | Embedded PostgreSQL for zero-Docker DB |
| `github.com/lestrrat-go/jwx/v2` | JWT signing for idplite (already transitive via platform) |

## Sub-Agent Parallelization

For maximum speed during Phase 0 implementation, these tasks can run in parallel after repo restructure (0a):

```
                    ┌─ Agent A: idplite (0b)
                    │   OIDC discovery + JWKS + token endpoint
                    │
 0a. Repo setup ────┼─ Agent B: Config loader + embedded-postgres (0c + 0d)
 (sequential,       │   config.Loader interface + PG lifecycle
  must go first)    │
                    ├─ Agent C: KAS key generation (0e)
                    │   RSA-2048 + EC secp256r1 key pairs
                    │
                    └─ Agent D: main.go + integration (0g)
                        Orchestrate startup, wire everything
                        (depends on A, B, C completing)
```

## Active Workstreams

- **Phase 0: Wrap-and-Shim (current — 2026-02-21)**
  - Remove old scaffolding, restructure repo
  - Build idplite, config loader, embedded-postgres wrapper, keygen
  - Wire up main.go with server.Start()
  - Integration test with otdfctl

- **Phase 1: SQLite Shim (future)**
  - Replace embedded-postgres with modernc.org/sqlite
  - True single binary with no runtime downloads

- **Phase 2: In-Memory Mode (future)**
  - Ephemeral mode for testing/CI

## Build, Test & Development Commands

```bash
go build ./...                    # build all packages
go build -o tdflite ./cmd/tdflite # build the single binary
go test ./...                     # run all tests
go test -race ./...               # tests with race detector
go vet ./...                      # static analysis
gofmt -s -w .                     # format code
go mod tidy                       # clean up dependencies
./tdflite serve                   # run the daemon
```

## Coding Style

**Go idiomatic.** `gofmt` defaults. No heavy frameworks — stdlib `net/http`, `crypto/*` where possible.

- Use `context.Context` as first param on methods that do I/O
- Wrap errors with `fmt.Errorf("context: %w", err)`
- Name files after primary export
- Keep it simple — we're wrapping the platform, not reimplementing it

**Configuration:** YAML for daemon config (OpenTDF format), JSON for identity data.

## Testing Expectations

Unit/integration tests co-located beside code (`foo_test.go`).
Table-driven tests preferred.
Race detector: `go test -race ./...`

### OpenTDF Compatibility
- TDFLite must serve the same API surface as the real OpenTDF platform
- Test with `otdfctl` CLI as the integration test
- All ConnectRPC + gRPC + REST endpoints must work

### Documentation Maintenance Policy

**Principle**: Code and docs must stay in sync. Outdated docs are worse than no docs.

| Change Type | Docs to Update |
|-------------|----------------|
| **Strategy change** | QUICKCONTEXT.md, ARCHITECTURE.md, AGENTS.md |
| **New component** | ARCHITECTURE.md, AGENTS.md structure table |
| **Config change** | ARCHITECTURE.md config spec, config/tdflite.yaml |
| **Phase/milestone complete** | QUICKCONTEXT.md, TODO.md |
| **New issue discovered** | KNOWN_ISSUES.md |

### Quality Gates (run before every push)

```bash
go build ./...        # must compile
go test ./...         # all tests pass
go vet ./...          # no static analysis issues
gofmt -d .            # no formatting issues
```

## Commit & PR Guidelines

Use conventional prefixes (`feat:`, `fix:`, `refactor:`, `docs:`, `build:`, `test:`). Never commit secrets.

## TODO Tracking (MANDATORY PRE-COMMIT)

### Two-Tag System

| Tag | Meaning | Commit Allowed? |
|-----|---------|-----------------|
| `TODO:` | Untracked work | No — must track first |
| `TRACKED-TASK:` | In TODO.md/docs | Yes |

### Before Every Commit

```bash
# Find untracked TODOs (should be 0 before commit)
grep -rn "TODO:" --include="*.go" internal/ pkg/ cmd/

# If found: add to TODO.md, convert to TRACKED-TASK:, re-run check
```
