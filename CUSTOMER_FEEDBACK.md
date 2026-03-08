# TDFLite Customer Feedback — blindpipe Integration

**Date**: 2026-03-07
**Customer**: blindpipe (zero-knowledge collaborative office suite)
**Integration**: Browser-side TDF3 encrypt/decrypt via @opentdf/sdk v0.4.0 JS + Go SDK v0.13.0
**Contact**: Will Ackerly

This document captures every friction point, unclear error, and missing feature encountered while integrating TDFLite as the ABAC enforcement layer for blindpipe. Items are ordered by severity.

---

## P0 — Blockers (required manual fixes to get working)

### 1. `base_key` not populated in well-known config

**Problem**: After `tdflite serve` starts and provisioning completes, `/.well-known/opentdf-configuration` returns `"base_key": {}` (empty). The OpenTDF SDK requires a non-empty `base_key` to encrypt — without it, `createNanoTDF()` and `createZTDF()` fail with "missing BaseKey in WellKnownConfiguration".

**Root cause**: TDFLite's auto-provisioning (`provision.Provision()`) creates namespaces, attributes, and subject mappings, but does NOT register the KAS or its keys in the platform's policy database. The `base_keys` table stays empty, so `SetBaseKeyOnWellKnownConfig()` has nothing to publish.

**Fix applied**: Added `ProvisionKASRegistration()` to `internal/provision/provision.go` — calls `CreateKeyAccessServer` + `CreateKey` + `SetBaseKey` via ConnectRPC after policy provisioning.

**Recommendation**: This should be part of the standard `tdflite serve` bootstrap. Every TDFLite instance should auto-register its KAS keys. The error message "missing BaseKey" gives zero indication that KAS registration is needed — consider adding a startup health check that warns if base_key is empty.

### 2. Relative paths in crypto provider config

**Problem**: `loader.DefaultConfig()` generates relative paths like `data/kas-private.pem` for the crypto provider keys. When running in Docker (or any environment where CWD ≠ the project root), `os.ReadFile("data/kas-private.pem")` fails silently — the KAS starts but can't unwrap any DEKs.

**Symptom**: "no valid KAOs" on every rewrap attempt. No error logged during startup. The crypto provider reports successful key loading even though it may have loaded the wrong files or failed silently.

**Fix applied**: `DefaultConfig()` now takes `dataDir string` and builds absolute paths via `filepath.Join(dataDir, "kas-private.pem")`.

**Recommendation**: Always use absolute paths in generated configs. Add a startup validation that verifies each crypto key file exists and is readable, with a clear error like "KAS crypto key not found: /data/kas-private.pem — check --data-dir flag".

### 3. EC-wrapped TDF disabled by default

**Problem**: When the `base_key` is EC (secp256r1), the SDK encrypts with `ec-wrapped` key type. But the KAS rejects it with "ec-wrapped not enabled" because `ec_tdf_enabled` defaults to `false`.

**Symptom**: "no valid KAOs" (same as #2). The real error "ec-wrapped not enabled" is logged at WARN level but easily missed in verbose startup logs.

**Fix applied**: Added `ec_tdf_enabled: true` to the generated KAS config in `loader.go`.

**Recommendation**: If the platform has EC keys configured, `ec_tdf_enabled` should default to `true` automatically. Or better: remove the flag entirely and always support EC-wrapped if EC keys are present. The current behavior is a footgun — you configure EC keys but they silently don't work for wrapping.

### 4. `public_client_id` missing from OIDC discovery

**Problem**: `otdfctl` and the OpenTDF SDK look for `public_client_id` in the well-known configuration's `idp` section. TDFLite's idplite doesn't include it, and even if it did, the platform's `OIDCConfiguration` struct drops unknown fields during unmarshalling.

**Symptom**: `otdfctl` hangs or fails with "public_client_id not found in well-known idp configuration". No clear error path.

**Fix applied**: Added `public_client_id: "opentdf-public"` to idplite's discovery response. Patched the vendored `OIDCConfiguration` struct to include the field.

**Recommendation**: This should be a standard field in the `OIDCConfiguration` struct upstream. Any IdP that TDFLite supports should include it. The error message from the SDK/CLI should say exactly what's expected and where to configure it.

---

## P1 — Significant Usability Issues

### 5. Attribute FQN namespace confusion

**Problem**: The attribute FQN format is `{namespace}/attr/{name}/value/{val}`. New users naturally construct FQNs using the KAS URL (e.g., `http://localhost:8085/attr/classification_level/value/top_secret`). But the platform resolves FQNs by **namespace** (e.g., `https://blindpipe.local/attr/...`). Using the wrong prefix causes "resource FQNs not found in memory" — a 403 that looks like an ABAC denial.

**Symptom**: "encountered unknown FQN on resource" + "resource is not able to be entitled" → 403 Permission Denied. The user thinks their clearance is wrong, but it's actually the FQN prefix.

**Recommendation**:
- The error message should say: "Attribute FQN 'http://localhost:8085/attr/...' not found. Did you mean 'https://blindpipe.local/attr/...'? Registered namespaces: [blindpipe.local]"
- Document the FQN format prominently in the README with a warning about this common mistake
- Consider auto-resolving FQNs that use the KAS URL by mapping them to the registered namespace

### 6. "no valid KAOs" is an opaque error

**Problem**: The error "no valid KAOs" is the KAS's catch-all for "I couldn't decrypt any of the Key Access Objects in this TDF". But there are at least 5 different root causes: wrong key files, EC not enabled, key ID mismatch, CWD issue, wrong algorithm. The error message gives no indication which cause applies.

**Recommendation**: Log the specific failure for EACH KAO before the aggregate error. For example:
- "KAO[0] kid=e1: ec-wrapped not enabled (set ec_tdf_enabled=true in KAS config)"
- "KAO[0] kid=r1: key not found (check crypto provider config for kid 'r1')"
- "KAO[0] kid=e1: decrypt failed: private key file not readable at /data/kas-ec-private.pem"

### 7. Docker requires `TDFLITE_KAS_EXTERNAL_URL`

**Problem**: When TDFLite runs in Docker with port mapping (e.g., host:8085 → container:8080), the KAS registers itself with the internal URL (`http://localhost:8080`). The SDK reads this from well-known and tries to reach `localhost:8080` from outside Docker — which fails.

**Fix applied**: Added `TDFLITE_KAS_EXTERNAL_URL` env var. If set, the KAS is registered with the external URL.

**Recommendation**: Auto-detect this from Docker networking or make it a first-class `--kas-url` flag. Document the Docker port mapping requirement prominently.

### 8. `SetBaseKey` "no rows in result set" error on first boot

**Problem**: On first boot, `SetBaseKey` logs `ERROR: no rows in result set (SQLSTATE 20000)` because the `base_keys` table's upsert trigger tries to update a non-existent row. The operation still succeeds (insert), but the error log is alarming.

**Recommendation**: Suppress or downgrade this to DEBUG. It's expected on first boot.

---

## P2 — Developer Experience Improvements

### 9. No smoke test for the full encrypt/decrypt pipeline

**Problem**: TDFLite has unit tests and integration tests for individual components, but no single test that verifies "I can start TDFLite and encrypt/decrypt a document". The `scripts/e2e-test.sh` requires `otdfctl` which has version compatibility issues.

**Fix applied**: Added `tests/e2e_encrypt_decrypt_test.go` — a Go test that does the full round-trip using the vendored SDK.

**Recommendation**: This should be a standard `go test -tags e2e ./tests/` that runs in CI. Consider also adding a `tdflite verify` subcommand that does a self-test after startup.

### 10. SDK version compatibility matrix

**Problem**: We encountered multiple failures from version mismatches:
- `otdfctl` v0.29.0 hangs against platform v0.13.0
- `otdfctl` v0.14.0 fails on `public_client_id`
- `@opentdf/sdk` v0.4.0 (JS) NanoTDF rewrap uses a format the platform v0.13.0 doesn't support
- `@opentdf/sdk` v0.4.0 (JS) TDF3 works but attribute FQN handling differs from Go SDK

**Recommendation**: Document a compatibility matrix: "TDFLite vX.Y works with @opentdf/sdk JS vA.B, Go SDK vC.D, otdfctl vE.F". Pin and test these versions in CI.

### 11. NanoTDF rewrap not supported in platform v0.13.0

**Problem**: The NanoTDF format uses a different rewrap request body (with `keyAccess.header` containing the full NanoTDF header) than TDF3 (standard v2 protobuf). The KAS handler at v0.13.0 only handles TDF3 rewrap. NanoTDF rewrap silently fails with "invalid request body".

**Recommendation**: Either support NanoTDF rewrap or return a clear error: "NanoTDF rewrap not supported — use TDF3 format". The current "invalid request body" error gives no hint about the format mismatch.

### 12. `CreateKey` validation errors are cryptic

**Problem**: When calling `CreateKey`, the validation errors are protobuf-style and hard to parse:
- `"private_key_ctx.key_id: value length must be at least 1 characters [string.min_len]"` — means you forgot `keyId` in `privateKeyCtx`
- `"expected base64 encoded value"` — means the PEM needs base64 encoding
- `"The wrapped_key is required if key_mode is KEY_MODE_CONFIG_ROOT_KEY"` — means you need to wrap the private key

**Recommendation**: Add human-readable error descriptions or a troubleshooting guide. The chain of requirements (mode→wrapping→encoding) is non-obvious.

---

## P3 — Nice to Have

### 13. Auto-provisioning should be atomic

**Problem**: If provisioning partially fails (e.g., attributes created but subject mappings fail), restarting TDFLite hits "already exists" errors. The provisioning is idempotent for creates but doesn't handle partial state well.

**Recommendation**: Consider a "provisioned" marker file. If provisioning completed successfully, skip it on restart. If not, retry the full sequence.

### 14. Health endpoint should report provisioning status

**Problem**: `/healthz` returns `SERVING` before provisioning completes. A client that checks health and immediately encrypts will fail because attributes aren't provisioned yet.

**Recommendation**: Either block `/healthz` until provisioning completes, or add a `provisioned: true/false` field to the health response.

### 15. KAS cert vs raw public key confusion

**Problem**: TDFLite generates self-signed X.509 **certificates** (not raw public keys) for the KAS. The `kas-cert.pem` files contain certificates, but many parts of the API and config refer to them as "public keys". This creates confusion about whether to send a cert or a raw key.

**Recommendation**: Be consistent in naming — if files are certs, call them `.cert.pem`. If the API expects certs, document it. Currently `publicKeyCtx.pem` accepts both but doesn't say so.

---

## What Worked Well

- **Sealed policy bundles**: Elegant solution for key+policy packaging. SSH key encryption is a nice touch.
- **Embedded PostgreSQL**: Zero-dependency database is huge for DX. First-run download is slow but subsequent starts are fast.
- **Claims-based entity resolution**: Not needing Keycloak is a massive simplification for dev environments.
- **ConnectRPC API**: Clean, well-typed API for provisioning. The gRPC-Web compatibility is appreciated for browser clients.
- **ABAC evaluation**: Once attributes are correctly provisioned, the hierarchy/allOf/anyOf evaluation works perfectly. The audit logs are detailed and useful.

---

## Summary of Fixes We Contributed

| Fix | File | Description |
|-----|------|-------------|
| KAS auto-registration | `internal/provision/provision.go` | CreateKAS + CreateKey + SetBaseKey during provisioning |
| Absolute crypto paths | `internal/loader/loader.go` | `DefaultConfig` takes `dataDir`, builds absolute paths |
| EC TDF enabled | `internal/loader/loader.go` | `ec_tdf_enabled: true` in KAS config |
| External KAS URL | `cmd/tdflite/main.go` | `TDFLITE_KAS_EXTERNAL_URL` env var for Docker |
| `public_client_id` | `internal/idplite/idplite.go` | Added to OIDC discovery response |
| OIDC struct patch | `vendor/.../auth/discovery.go` | `PublicClientID` field in `OIDCConfiguration` |
| E2E test | `tests/e2e_encrypt_decrypt_test.go` | Go test proving full TDF3 round-trip |
