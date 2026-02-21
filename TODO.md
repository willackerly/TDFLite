# TODO

**Last synced:** 2026-02-21

## Phase 1: Policy Service + Store

- [ ] Implement policy HTTP handlers (namespace CRUD)
- [ ] Implement attribute definition CRUD handlers
- [ ] Implement attribute value CRUD handlers
- [ ] Implement subject mapping CRUD handlers
- [ ] Implement resource mapping CRUD handlers
- [ ] Implement key access registry handlers
- [ ] Wire policy handlers to server mux
- [ ] Implement jsonfile store (memory + JSON persistence)
- [ ] Add unit tests for in-memory store
- [ ] Add integration tests for policy endpoints

## Phase 2: KAS + Crypto

- [ ] Implement software crypto provider (RSA-2048, EC secp256r1, AES-256-GCM)
- [ ] Implement KAS PublicKey endpoint
- [ ] Implement KAS Rewrap endpoint
- [ ] Wire KAS handlers to server mux
- [ ] Add unit tests for crypto operations
- [ ] Add integration tests for KAS endpoints

## Phase 3: Built-in OIDC IdP

- [ ] Implement OIDC discovery endpoint
- [ ] Implement JWKS endpoint
- [ ] Implement token endpoint (client_credentials grant)
- [ ] Implement token endpoint (password grant)
- [ ] Implement token validation
- [ ] Load identities from JSON file
- [ ] Wire IdP routes to server mux
- [ ] Wire auth middleware to protected routes
- [ ] Add tests for token issuance and validation

## Phase 4: Authorization Engine

- [ ] Implement ABAC rule evaluation (ALL_OF, ANY_OF, HIERARCHY)
- [ ] Implement GetEntitlements
- [ ] Implement GetDecisions
- [ ] Implement JWT-based entity resolution
- [ ] Wire authorization handlers to server mux
- [ ] Add tests for ABAC rule evaluation

## Phase 5: End-to-End TDF

- [ ] Implement TDF3 encryption (manifest + encrypted payload)
- [ ] Implement TDF3 decryption
- [ ] Integration test: encrypt → decrypt round-trip
- [ ] Test with `otdfctl` CLI for OpenTDF compatibility
- [ ] NanoTDF support (stretch goal)

## Code Debt

(None yet — fresh project)
