# Client-Facing Concepts — What Real Clients Use

Inventory of concepts that might fail if we don't implement them.
Source: TDFBot analysis, platform-configs, OpenTDF SDK behavior.

## Currently Implemented (idplite)
- OIDC discovery (/.well-known/openid-configuration)
- JWKS endpoint (/jwks)
- Token endpoint (/token) — client_credentials and password grants
- Standard JWT claims: iss, sub, aud, iat, exp, jti
- Custom claims: client_id, preferred_username, realm_access.roles
- Arbitrary custom claims via Identity.CustomClaims (classification_level, sci, etc.)
- Configurable audience (separate from issuer)

## Used by otdfctl / OpenTDF SDK
- `--with-client-creds` → client_credentials grant (IMPLEMENTED)
- Token audience must match `server.auth.audience` (IMPLEMENTED)
- `client_id` claim in token for authorization (IMPLEMENTED)
- `realm_access.roles` for admin/standard role check (IMPLEMENTED)

## Used by TDFBot / Keycloak (DEFERRED)
These are Keycloak endpoints/features TDFBot uses that we do NOT implement:
- `/admin/realms/{realm}/users` — Keycloak admin API for user management
- `/admin/realms/{realm}/clients` — Client management
- `/auth/realms/{realm}/protocol/openid-connect/token` — Keycloak-specific token path
- Token introspection endpoint
- Userinfo endpoint
- Refresh token grant type
- DPOP (disabled in our config, but platform supports it)
- Client scopes and protocol mappers

## Subject Mapping Selector Differences
- **TDFBot (Keycloak entity resolution):** `.attributes.classification_level[]`
  Keycloak admin API returns user attributes in this shape
- **TDFLite (claims mode):** `.classification_level`
  JWT custom claims are top-level, direct selector

## Policy Concepts in Use
- Attribute rules: HIERARCHY (classification), ALL_OF (SCI, releasable_to)
- Subject condition operators: IN (single value match), IN_CONTAINS (array membership)
- FQN format: `https://<namespace>/attr/<name>/value/<value>`
- Actions: STANDARD_ACTION_DECRYPT, STANDARD_ACTION_TRANSMIT

## Platform Config Patterns (from platform-configs)
- `server.auth.policy.client_id_claim` — claim path for client ID
- `server.auth.policy.username_claim` — claim path for username
- `server.auth.policy.groups_claim` — claim path for group/role membership
- `services.entityresolution.mode: claims` — skip Keycloak, use JWT directly
- `server.cryptoProvider.type: standard` — local key files for KAS

## Potential Future Issues
1. **SDK token refresh**: SDKs may expect refresh_token support for long operations
2. **Token introspection**: Some admin tools may call introspection endpoint
3. **Userinfo**: Some OIDC clients expect /userinfo endpoint
4. **PKCE/Authorization code**: Web UIs need authorization_code grant
5. **Logout endpoint**: Needed for session management
6. **Client registration**: Dynamic client registration for new apps
