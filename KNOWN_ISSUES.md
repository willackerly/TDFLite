# Known Issues

**Last Updated:** 2026-02-21

## Active Issues

None yet — project is in initial scaffolding phase.

## Gotchas

### Go Module Path
The module is `github.com/willnorris/tdflite`. If you fork or move the repo, update `go.mod` and all import paths.

### No Auth Enforcement Yet
Auth middleware exists but is not wired in. All endpoints are currently unauthenticated. This will be addressed in Phase 3.

### Placeholder Packages
Several packages contain only placeholder comments (no Go code):
- `internal/store/jsonfile/` — JSON persistence not yet implemented
- `internal/authn/idplite/` — Built-in IdP not yet implemented
- `internal/authz/engine/` — ABAC engine not yet implemented

These will be filled in during their respective phases.
