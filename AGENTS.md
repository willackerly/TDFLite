# Repository Guidelines

## Read Before Coding

**Quick start (new agent):**
1. `QUICKCONTEXT.md` → 30-second orientation, current state of the world
2. `KNOWN_ISSUES.md` → active blockers, gotchas, common errors
3. `TODO.md` → consolidated task tracking

**Full context:**
4. `README.md` → repo purpose + quick start
5. `AGENTS.md` (this file) → norms
6. `docs/README.md` → documentation tree

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
- Creating new internal subsystem packages
- Protocol changes (API surface, wire formats)
- Breaking changes affecting existing callers

### Never Without Explicit Request
- `git push --force` to shared branches
- `git reset --hard` on commits others have
- Deleting production data
- Modifying production secrets

**Rule of thumb:** If it follows existing patterns and is reversible → just do it. If it establishes new patterns or is hard to undo → plan mode.

---

## Cold Start Methodology (MANDATORY for New Agent Sessions)

**When starting a new session, always perform this sanity check before acting:**

### Step 1: Verify Document Freshness (5 min)
Don't trust docs blindly. Cross-reference against actual state:

```bash
# 1. Check current branch (docs may reference wrong branch)
git branch --show-current
git log --oneline -10

# 2. Compare QUICKCONTEXT.md branch claim against reality
grep -i "branch" QUICKCONTEXT.md

# 3. Check TODO.md "Last synced" date
head -10 TODO.md

# 4. Verify Active Workstreams match recent commits
git log --oneline -20 | head -10
```

### Step 2: Identify Discrepancies
Look for these common drift patterns:
- **Branch mismatch**: Docs say one branch, you're on another
- **Phase status lag**: Code shows Phase N complete but docs say Phase N-1
- **Stale dates**: "Last Updated" > 2 weeks old warrants scrutiny
- **Missing features**: Grep for features in code vs docs

### Step 3: Update Before Acting
If you find discrepancies:
1. **Minor drift**: Update the doc inline while working
2. **Major drift**: Update docs FIRST, then proceed with task
3. **Conflicting signals**: Ask user for clarification

### Step 4: Strategic Assessment
Before diving into code, ask:
- What's the **actual** current state? (git log, file structure)
- What's the **documented** next step? (TODO.md, AGENTS.md workstreams)
- Do they align? If not, which is authoritative?
- Are there **blocked** items I should avoid?

### Why This Matters
Multiple agents work async on this codebase. Docs drift when agents complete work but don't update all references. Taking 5 minutes to verify state prevents hours of wasted effort on outdated priorities.

## Project Structure & Module Ownership

TDFLite is a single Go module (`github.com/willnorris/tdflite`) with a flat internal structure.

**Key principle: Interface-first, swap-ready.** Every subsystem defines a Go interface at the package root. Lightweight "lite" implementations live in sub-packages. Heavier backends can be swapped in without changing callers.

| Package | Responsibility | Interface File |
|---------|---------------|----------------|
| `cmd/tdflite/` | Binary entry point, CLI flags | — |
| `internal/server/` | HTTP/gRPC server wiring, router, middleware | — |
| `internal/config/` | YAML config loading, env var overlay | — |
| `internal/store/` | Persistence for policy, keys, identity state | `store.go` |
| `internal/authn/` | Authentication, OIDC token validation, IdP | `authn.go` |
| `internal/authz/` | Authorization decisions (ABAC engine) | `authz.go` |
| `internal/kas/` | Key Access Server (PublicKey, Rewrap) | `kas.go` |
| `internal/policy/` | Policy CRUD (namespaces, attributes, mappings) | `policy.go` |
| `internal/entityresolution/` | Resolve entities to attribute sets | `resolver.go` |
| `internal/crypto/` | Cryptographic operations (RSA, EC, AES) | `crypto.go` |
| `pkg/tdf/` | TDF and NanoTDF format library (public) | `tdf.go` |

## Active Workstreams

- **Phase 0: Scaffolding (in progress 2026-02-21)**
  - Project structure, interfaces, CLAUDE.md/AGENTS.md
  - Go module init, directory layout
  - **Remaining:** wire up main.go, basic config loading

- **Phase 1: Policy Service + Store**
  - In-memory store with JSON file persistence
  - Policy CRUD handlers (namespaces, attributes, values, mappings)
  - Pending: all implementation

- **Phase 2: KAS + Crypto**
  - Software-based RSA/EC key management
  - PublicKey and Rewrap endpoints
  - Pending: all implementation

- **Phase 3: Built-in OIDC IdP**
  - Lightweight IdP with JSON-backed identity store
  - OIDC discovery, token issuance, JWKS
  - Pending: all implementation

- **Phase 4: Authorization Engine**
  - ABAC evaluation (ALL_OF, ANY_OF, HIERARCHY rules)
  - GetEntitlements, GetDecisions
  - Pending: all implementation

- **Phase 5: End-to-End TDF**
  - TDF3 encrypt/decrypt using `pkg/tdf`
  - Integration with KAS, policy, authz
  - Pending: all implementation

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

## Coding Style & File Summaries

**Go idiomatic.** `gofmt` defaults. No heavy frameworks — stdlib `net/http`, `crypto/*`, `encoding/json` where possible.

**Interface-first conventions:**
- Interface definitions go in the package root file (e.g., `store/store.go`)
- Implementations go in sub-packages (e.g., `store/memory/memory.go`)
- Constructors return the interface type: `func New(...) store.Store`
- Use `context.Context` as first param on all interface methods
- Wrap errors with `fmt.Errorf("context: %w", err)`
- Name files after primary export

**Configuration:** YAML for daemon config, JSON for runtime state (identity, persisted policy).

## Testing Expectations

Unit/integration tests co-located beside code (`foo_test.go`).
Test against interfaces, not concrete types.
Table-driven tests preferred.
Race detector in CI: `go test -race ./...`

### Contract-First Policy

- OpenTDF protocol compatibility is the contract
- API endpoints must match OpenTDF's gRPC service definitions
- Existing OpenTDF SDKs and `otdfctl` should work against TDFLite
- Test with `otdfctl` as an integration test

### Documentation Maintenance Policy

**Principle**: Code and docs must stay in sync. Outdated docs are worse than no docs.

**After every code change or task completion**, walk the doc tree and update affected files:

| Change Type | Docs to Update |
|-------------|----------------|
| **New feature/module** | Package README, AGENTS.md workstreams |
| **API change** | Protocol docs, endpoint docs |
| **Interface change** | CLAUDE.md architecture table, AGENTS.md structure table |
| **Bug fix** | Relevant README if it clarifies behavior; remove stale warnings |
| **Config change** | CLAUDE.md env vars, config/tdflite.yaml comments |
| **Phase/milestone complete** | AGENTS.md workstreams, QUICKCONTEXT.md |
| **New file/module** | Parent folder's README or header comment |

#### Archive Policy

**When to archive:**
- Phase 100% complete and no longer changing
- Planning doc for approach not implemented

**Never archive:** `AGENTS.md`, `QUICKCONTEXT.md`, `TODO.md`, `KNOWN_ISSUES.md`, `CLAUDE.md`

**How to archive:**
1. Move to `docs/archive/YYYY-MM-DD-description/`
2. Add header: `ARCHIVED: [DATE] | REASON: [reason] | CURRENT: [link to replacement]`
3. Update `docs/archive/README.md` index
4. Remove link from parent README

### Quality Gates (run before every push)

```bash
go build ./...        # must compile
go test ./...         # all tests pass
go vet ./...          # no static analysis issues
gofmt -d .            # no formatting issues (should be empty)
```

**Skip Policy**
- No skipping tests that validate interface contracts.
- Temporary skips must include a `TRACKED-TASK:` comment with a TODO.md reference.

## Commit & PR Guidelines

Use conventional prefixes (`feat:`, `fix:`, `refactor:`, `docs:`, `build:`, `test:`). PRs must describe user-facing impact, list touched packages, and note interface changes. Never commit secrets.

## TODO Tracking (MANDATORY PRE-COMMIT)

**This is a hard requirement for all agents.**

### Two-Tag System

| Tag | Meaning | Commit Allowed? |
|-----|---------|-----------------|
| `TODO:` | Untracked work | No — must track first |
| `TRACKED-TASK:` | In TODO.md/docs | Yes |

### Before Every Commit

```bash
# 1. Find untracked TODOs (should be 0 before commit)
grep -rn "TODO:" --include="*.go" internal/ pkg/ cmd/

# 2. If untracked TODOs found:
#    - Add to TODO.md
#    - Convert TODO: → TRACKED-TASK: in code
#    - Re-run check

# 3. Only commit when untracked TODOs = 0
```
