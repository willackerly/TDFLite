# Documentation Improvement Recommendations

Gotchas, non-obvious behaviors, and things future users should never have to guess.
Covers both TDFLite and upstream OpenTDF platform.

## Casbin Role Naming Convention

**Problem:** The platform's built-in casbin policy expects JWT roles prefixed with `opentdf-` (e.g., `opentdf-admin`, `opentdf-standard`). If you emit roles as just `admin` or `standard`, all API calls return 403 — with no hint about why.

**Where it's defined:** `service/internal/auth/casbin.go` lines 86-93 add default group mappings:
```
g, opentdf-admin, role:admin
g, opentdf-standard, role:standard
```

**Fix:** Ensure your IdP emits `opentdf-admin` and `opentdf-standard` in the `realm_access.roles` JWT claim (or wherever `groups_claim` points).

**Recommendation for OpenTDF docs:** Document the expected role names prominently in the auth configuration guide. The casbin policy is embedded and not visible without reading source code.

## Token Audience Must Match server.auth.audience

**Problem:** If the JWT `aud` claim doesn't match the `server.auth.audience` config value, all authenticated requests return 401 with just `"unauthenticated"` — no mention of audience mismatch.

**Where it's validated:** `service/internal/auth/authn.go` line 515: `jwt.WithAudience(a.oidcConfiguration.Audience)`

**Recommendation:** Log a more specific error when audience validation fails (e.g., "token audience [X] does not match configured audience [Y]").

## Entity Resolution Mode: claims vs keycloak

**Problem:** Without `services.entityresolution.mode: claims` in config, the platform tries to connect to Keycloak's admin API for entity resolution. This silently fails or hangs if Keycloak isn't running.

**Recommendation:** Document that `claims` mode reads JWT claims directly, making it the right choice for any non-Keycloak IdP. Currently this is buried in the config schema with no explanation of the behavior difference.

## Connect Protocol API — Enum Naming

**Problem:** The Connect protocol expects full protobuf enum names in JSON (e.g., `ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY`, not `HIERARCHY`). This is standard protobuf JSON encoding but not documented in the OpenTDF API guide.

**Also:** JSON field names use camelCase (`namespaceId`, `attributeValueId`), not snake_case, even though the protobuf definitions use snake_case. This is standard protobuf JSON mapping but trips people up.

**Recommendation:** Provide curl examples for common provisioning operations (create namespace, create attribute, create subject mapping) in the OpenTDF docs.

## Attribute Hierarchy Order

**Problem:** For `HIERARCHY` rule attributes, the order of values matters — first value is highest priority. This determines access control decisions but isn't documented alongside the attribute creation API.

**Recommendation:** Document that `values: ["TOP_SECRET", "SECRET", "CONFIDENTIAL", "UNCLASSIFIED"]` means TOP_SECRET > SECRET > CONFIDENTIAL > UNCLASSIFIED.

## Subject Mapping Selector Format (Claims Mode)

**Problem:** In claims mode, `subject_external_selector_value` is a dot-path into the JWT claims (e.g., `.classification_level`). In Keycloak mode, it's a path into the Keycloak admin API response (e.g., `.attributes.classification_level[]`). The selector format depends on the entity resolution mode, but this isn't documented.

**Recommendation:** Provide examples of subject mapping selectors for both claims mode and Keycloak mode side by side.

## Array JWT Claims Require `[]` Selector Suffix

**Problem:** JWT claims that are arrays (e.g., `"sci_control_system": ["SI", "HCS", "TK"]`) are flattened into indexed keys like `.sci_control_system[0]`, `.sci_control_system[]`. If your subject mapping selector uses `.sci_control_system` (no brackets), the flattening lookup returns empty — the condition silently fails, and the user is denied access.

**Where it's defined:** `lib/flattening/flatten.go` — arrays produce keys with `[index]` and `[]` suffixes. `GetFromFlattened()` does exact key matching.

**Correct selectors for claims mode:**
- String claims: `.classification_level` (no brackets needed)
- Array claims: `.sci_control_system[]` or `.releasable_to[]` (brackets required)

**Also:** With `[]` selectors, each array element is individually available, so use `IN` (exact match) rather than `IN_CONTAINS` (substring match). `IN_CONTAINS` does `strings.Contains()` on the string representation, which can cause false positives.

**Recommendation:** Document that array claim selectors MUST use the `[]` suffix. This is the single most confusing aspect of claims-mode subject mappings.

## Attribute Values Are Lowercased

**Problem:** The platform lowercases attribute value names on creation. If you pass `"TOP_SECRET"`, the FQN becomes `https://ns/attr/name/value/top_secret`. This means encrypt commands must use lowercase FQNs, but subject mapping selectors still match the original JWT claim value (case-sensitive).

**Example:** You create value `"TOP_SECRET"` → FQN is `.../value/top_secret`. When encrypting, use `--attr .../value/top_secret`. But the JWT still has `"classification_level": "TOP_SECRET"` (uppercase), and subject mapping conditions use `IN ["TOP_SECRET"]`.

**Recommendation:** Document the case normalization behavior. It's particularly confusing because it only affects the attribute FQN, not the subject mapping condition values.

## Subject Mapping Action Format — Deprecated Enum vs Name

**Problem:** The `Action` protobuf has a deprecated `standard`/`custom` oneof AND a newer `name` string field. If you send `{"standard": "STANDARD_ACTION_DECRYPT"}`, the validation rejects it with "Action name or ID must not be empty if provided" — because it checks the `name` and `id` fields, not the deprecated oneof.

**Correct format:** Use `{"name": "read"}` (replaces STANDARD_ACTION_DECRYPT) and `{"name": "create"}` (replaces STANDARD_ACTION_TRANSMIT). Action names are short lowercase strings: `read`, `create`, `update`, `delete`, or custom names.

**Where it's defined:** `service/policy/objects.proto` lines 129-156 (Action message), `service/policy/db/actions.go` lines 16-22 (standard action names).

**Recommendation:** Document the action name migration prominently. The `standard` oneof still compiles and appears in generated code, but the validation CEL expression only checks `name`/`id`.

## KAS Registry "No Rows" Warning

**Problem:** On startup, the KAS registry logs `ERROR: no rows in result set`. This is non-fatal but alarming. It means no KAS servers are registered yet.

**Recommendation:** Downgrade to WARN or INFO, and add context: "No KAS servers registered. Register via the KAS registry API or auto-registration will occur on first encrypt."
