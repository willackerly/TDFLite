# CLAUDE.md

Project instructions for Claude Code. These override defaults—follow them exactly.

## Project: TDFLite

A **thin wrapper binary** around the real [OpenTDF platform](https://github.com/opentdf/platform) that eliminates all infrastructure dependencies. Starts embedded PostgreSQL + built-in OIDC IdP, then calls the real `server.Start()`. Full OpenTDF functionality. Zero Docker. One binary.

**Strategy:** Wrap, don't rewrite. See `docs/ARCHITECTURE.md` for full details.

## Cold Start (New Agent?)

**Read in order (5 min total):**
1. `QUICKCONTEXT.md` → 30-second orientation, current state
2. `KNOWN_ISSUES.md` → blockers, gotchas, common errors
3. `TODO.md` → what needs doing

**Then deep dive:**
4. `docs/ARCHITECTURE.md` → full architecture plan, component specs, config format
5. `AGENTS.md` → norms, workstreams, doc maintenance policy

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

- `cmd/tdflite/` — Main binary: embedded-postgres → idplite → server.Start()
- `internal/idplite/` — Built-in OIDC IdP (discovery, JWKS, token endpoint)
- `internal/loader/` — Custom `config.Loader` for injecting our infrastructure
- `internal/embeddedpg/` — Embedded PostgreSQL lifecycle wrapper
- `internal/keygen/` — KAS key pair generation (RSA + EC) on first run
- `config/` — Default `tdflite.yaml` in OpenTDF config format
- `data/` — Runtime state: identity JSON, generated keys, Postgres data
- `docs/` — Documentation (especially `ARCHITECTURE.md`)

## Key Dependencies

| Dependency | Purpose |
|-----------|---------|
| `github.com/opentdf/platform/service` | The real OpenTDF platform |
| `github.com/fergusstrange/embedded-postgres` | Zero-Docker embedded PostgreSQL |
| `github.com/lestrrat-go/jwx/v2` | JWT signing for idplite |

## Coding Style

Go idiomatic. `gofmt` defaults. No framework dependencies—stdlib `net/http` and `crypto/*` where possible.

Name files after their primary export. Keep changes minimal—don't over-engineer.

Use `context.Context` as first parameter on methods that do I/O.
Use `error` returns, not panics. Wrap errors with `fmt.Errorf("context: %w", err)`.

**Important:** We are wrapping the OpenTDF platform, not reimplementing it. Our code should be minimal glue — idplite, config loader, embedded-postgres lifecycle, key generation, and the main orchestrator. Everything else comes from the platform.

## Testing

Co-locate unit tests beside code (`foo_test.go` next to `foo.go`).
Integration tests in `tests/` directory.
Use table-driven tests. Use `testify` only if already a dependency.
Test with `otdfctl` CLI for end-to-end validation.

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
2. **Security model changes** — Altering encryption, auth, or key management approach
3. **Protocol changes** — Modifying API surface, wire formats
4. **Breaking changes** — Changes that break existing callers

**When in doubt:** If a change follows existing patterns and is reversible, just do it. If it establishes a new pattern or is hard to undo, enter plan mode.

### Force Operations (require explicit user request)

- `git push --force` to shared branches
- `git reset --hard` on commits others might have
- Deleting production data or databases
- Modifying secrets/credentials in production

## Architecture

### Wrap-and-Shim Strategy

```
┌──────────────────────────────────────────────┐
│              tdflite binary (Go)             │
│                                              │
│  1. Start embedded-postgres (:15432)         │
│  2. Start idplite OIDC IdP (:15433)          │
│  3. Create custom config.Loader              │
│  4. Call server.Start() with options          │
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

See `docs/ARCHITECTURE.md` for full details including config spec, component details, and phased roadmap.

## Active Workstreams

- **Phase 0** — Wrap-and-shim: embedded-postgres + idplite + server.Start() (current)
- **Phase 1** — SQLite shim: replace embedded-postgres with modernc.org/sqlite (future)
- **Phase 2** — In-memory mode: ephemeral mode for testing/CI (future)

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
