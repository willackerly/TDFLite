# Sealed Policy Bundle

The definitive reference for authoring, sealing, and operating TDFLite policy bundles.

---

## 1. Overview

A sealed policy bundle is a single JSON file that contains everything TDFLite needs to boot the full OpenTDF platform: attribute definitions, identity assignments, and encrypted cryptographic keys. Combined with an SSH private key, it replaces all configuration, provisioning scripts, key management, and identity provider setup.

The core promise: **one file + one SSH key = entire platform.**

Before the sealed policy bundle, deploying OpenTDF required assembling and coordinating at least seven separate artifacts:

| Artifact | Purpose |
|----------|---------|
| `docker-compose.yaml` | Orchestrate PostgreSQL, Keycloak, and the platform |
| `keycloak-realm.json` | Realm configuration, client registrations, roles |
| `opentdf.yaml` | Platform config: database credentials, auth settings, service endpoints |
| Keycloak admin scripts | Provision users, assign roles, configure clients |
| KAS key generation scripts | Generate RSA + EC key pairs, distribute to the platform |
| IdP client registration | Create OAuth2 clients, set grant types, configure scopes |
| TLS certificate management | Generate and distribute certificates |

The sealed policy bundle replaces all of them. You write a plain JSON file describing your access control policy (attributes, users, their clearances). You seal it with your SSH key. You boot the platform. Every access decision the system will ever make is derived from that one file, and every secret it needs is locked to your key.

---

## 2. Concepts

### Policy Bundle

The policy bundle is a JSON container with a fixed schema. It has two forms:

- **Plain** (`policy.json`) -- Human-authored, human-readable, version-controllable. Contains attribute definitions and identity assignments. No secrets.
- **Sealed** (`policy.sealed.json`) -- Machine-produced from the plain form. Contains everything in the plain form plus encrypted KAS keys, an encrypted IdP signing key, an SSH key fingerprint, and a cryptographic signature. Still JSON. Still readable. The policy itself is not encrypted -- only the keys are.

### Attributes

Attributes are the foundation of OpenTDF's attribute-based access control (ABAC). Each attribute has a name, a rule type, and a list of allowed values. When data is encrypted, it is tagged with one or more attribute values. When a user requests decryption, their claims are evaluated against those tags according to the attribute's rule.

Three rule types exist: `hierarchy`, `allOf`, and `anyOf`. Each has distinct semantics for how user claims are compared to data tags. See Section 4 for detailed descriptions.

### Identities

Identities represent the users and service accounts that interact with the platform. Each identity has a username (the JSON key), a set of attribute claims (which attribute values they possess), and optional overrides for credentials.

Identity claims must reference attributes defined in the same bundle. The claim value type (string vs. array of strings) is determined by the attribute's rule type.

### Sealing

Sealing transforms a plain policy file into a sealed bundle. The process:

1. Validates the policy -- every identity claim must reference a defined attribute with valid values.
2. Generates fresh KAS key pairs (RSA-2048 for legacy TDF, EC P-256 for nano TDF) and an IdP JWT signing key.
3. Encrypts all private keys using the SSH public key via age encryption.
4. Signs the entire bundle so any modification is detectable.
5. Writes the sealed file.

Sealing is a one-way transformation in the sense that you cannot extract the private keys without the corresponding SSH private key. However, the policy portion (attributes, identities, options) remains plaintext for auditability and diffability.

### The SSH Key as Root of Trust

Your SSH key is the master key for the entire platform. The KAS private keys -- the keys that actually decrypt protected data -- are encrypted with your SSH public key using age encryption. Without the corresponding SSH private key:

- The sealed bundle is inert. No one can start the platform.
- No one can decrypt any data, even with root access to the server.
- The platform refuses to boot because it cannot recover the KAS keys.

This design means your existing SSH key infrastructure doubles as your key management infrastructure. No separate HSMs, no key vaults, no certificate authorities. The same key you use to push to Git can boot your data protection platform.

Both Ed25519 and RSA SSH keys are supported.

**Alternative: passphrase mode.** For environments where SSH keys are not available -- quick demos, shared lab machines, CI runners -- TDFLite also supports sealing with a passphrase. Instead of encrypting KAS keys to an SSH public key, they are encrypted with a key derived from a passphrase using scrypt (via age's passphrase encryption). The tradeoff: you must enter the passphrase on every boot, and passphrase strength is your security boundary. SSH key mode is recommended for production; passphrase mode is there when you need the simplest possible path.

```bash
# Seal with passphrase (prompted interactively)
tdflite seal --policy policy.json --passphrase

# Boot with passphrase
tdflite serve --policy policy.sealed.json --passphrase
```

---

## 3. The Plain Policy File

A plain policy file is what you author by hand. It is the input to the `seal` command.

### Full Annotated Example

```json
{
  "version": 1,
  "namespace": "acme.example.com",
  "attributes": [
    {
      "name": "classification",
      "rule": "hierarchy",
      "values": ["top-secret", "secret", "confidential", "unclassified"]
    },
    {
      "name": "compliance",
      "rule": "allOf",
      "values": ["hipaa", "sox", "gdpr", "fedramp"]
    },
    {
      "name": "department",
      "rule": "anyOf",
      "values": ["engineering", "finance", "legal", "hr", "executive"]
    }
  ],
  "identities": {
    "alice": {
      "admin": true,
      "classification": "top-secret",
      "compliance": ["hipaa", "sox", "gdpr", "fedramp"],
      "department": ["engineering", "executive"]
    },
    "bob": {
      "classification": "secret",
      "compliance": ["hipaa"],
      "department": ["engineering"]
    },
    "carol": {
      "classification": "confidential",
      "compliance": ["sox", "gdpr"],
      "department": ["finance", "legal"],
      "password": "carol-custom-pw",
      "client_id": "carol-app",
      "client_secret": "carol-app-secret"
    }
  },
  "options": {
    "token_ttl": "30m",
    "default_actions": ["read", "create"]
  }
}
```

**Field-by-field breakdown:**

- `version` -- Schema version number. Currently must be `1`. Omitting it defaults to `1`.
- `namespace` -- The DNS-style namespace for attribute fully-qualified names (FQNs). Attributes become `https://{namespace}/attr/{name}/value/{value}`. Omitting it defaults to `tdflite.local`.
- `attributes` -- Array of attribute definitions. At least one required. See Section 4.
- `identities` -- Map of username to identity object. At least one required. See Section 5.
- `options` -- Optional overrides for power users. Omit to use defaults. See Section 10.

### Required vs. Optional Fields

| Field | Required | Default |
|-------|----------|---------|
| `version` | No | `1` |
| `namespace` | No | `tdflite.local` |
| `attributes` | Yes | -- |
| `attributes[].name` | Yes | -- |
| `attributes[].rule` | Yes | -- |
| `attributes[].values` | Yes (at least one) | -- |
| `identities` | Yes (at least one) | -- |
| `identities.{name}.admin` | No | `false` |
| `identities.{name}.password` | No | `{name}-secret` |
| `identities.{name}.client_id` | No | `{name}-client` |
| `identities.{name}.client_secret` | No | `{name}-secret` |
| `options` | No | `null` |
| `options.token_ttl` | No | Platform default |
| `options.default_actions` | No | `["read", "create"]` |

### Complete Defaults Table

| Setting | Default Value | Derivation |
|---------|---------------|------------|
| Namespace | `tdflite.local` | Hardcoded constant |
| Schema version | `1` | Hardcoded constant |
| Default actions | `["read", "create"]` | Applied to all auto-generated subject mappings |
| Identity password | `{username}-secret` | Username with `-secret` suffix |
| Identity client ID | `{username}-client` | Username with `-client` suffix |
| Identity client secret | `{username}-secret` | Username with `-secret` suffix |
| Admin service account | `opentdf` / `secret` | Built-in platform admin |
| SDK service account | `opentdf-sdk` / `secret` | Built-in SDK client |

---

## 4. Attribute Reference

### hierarchy

**Ordered values. First = highest. User level must be >= data level.**

Hierarchy attributes model linear classification systems where levels are ranked. The `values` array defines the ordering: the first element has the highest clearance, the last has the lowest.

When data is tagged with a hierarchy value (say `secret`), a user can access it if and only if their claim value is at the same level or higher in the hierarchy. A user with `top-secret` clearance can access `secret` data. A user with `confidential` clearance cannot.

**Claim type:** Scalar string. Each identity gets exactly one level in the hierarchy.

**Example -- Classification levels:**

```json
{
  "name": "classification",
  "rule": "hierarchy",
  "values": ["top-secret", "secret", "confidential", "unclassified"]
}
```

Identity claims for this attribute:

```json
{
  "alice": { "classification": "top-secret" },
  "bob":   { "classification": "secret" },
  "carol": { "classification": "confidential" },
  "dave":  { "classification": "unclassified" }
}
```

**Access matrix:**

| User / Data tagged as | top-secret | secret | confidential | unclassified |
|-----------------------|:----------:|:------:|:------------:|:------------:|
| alice (top-secret) | Yes | Yes | Yes | Yes |
| bob (secret) | No | Yes | Yes | Yes |
| carol (confidential) | No | No | Yes | Yes |
| dave (unclassified) | No | No | No | Yes |

**Key points:**
- Order matters. `["top-secret", "secret", "confidential"]` means `top-secret` > `secret` > `confidential`.
- An identity's claim must be one of the defined values. `"classification": "ultra"` will fail validation if `ultra` is not in the values array.
- The claim is always a single string, never an array. You have one level. `"classification": ["top-secret", "secret"]` is invalid.

### allOf

**Conjunctive. User must have ALL tagged values to access the data.**

allOf attributes model requirements where every tagged value must be satisfied. If data is tagged with `[hipaa, sox]`, the user must possess both `hipaa` and `sox` in their claims. Having only `hipaa` is insufficient.

**Claim type:** Array of strings. Each identity lists which values they possess.

**Example -- Compliance certifications:**

```json
{
  "name": "compliance",
  "rule": "allOf",
  "values": ["hipaa", "sox", "gdpr", "fedramp"]
}
```

Identity claims for this attribute:

```json
{
  "alice":   { "compliance": ["hipaa", "sox", "gdpr", "fedramp"] },
  "bob":     { "compliance": ["hipaa", "sox"] },
  "carol":   { "compliance": ["gdpr"] },
  "auditor": { "compliance": ["sox", "gdpr"] }
}
```

**Access scenarios:**

| Data tagged with | alice | bob | carol | auditor |
|------------------|:-----:|:---:|:-----:|:-------:|
| `[hipaa]` | Yes | Yes | No | No |
| `[hipaa, sox]` | Yes | Yes | No | No |
| `[sox, gdpr]` | Yes | No | No | Yes |
| `[hipaa, sox, gdpr, fedramp]` | Yes | No | No | No |

**Key points:**
- The claim must be an array, even for a single value: `"compliance": ["hipaa"]`, not `"compliance": "hipaa"`.
- The user must be a superset of the data's tags. Extra certifications do not hurt.
- An identity with no claim for an allOf attribute cannot access any data tagged with that attribute.

### anyOf

**Disjunctive. User must have AT LEAST ONE tagged value to access the data.**

anyOf attributes model broad access categories where belonging to any one qualifying group is sufficient. If data is tagged with `[engineering, finance]`, a user with either `engineering` or `finance` (or both) can access it.

**Claim type:** Array of strings. Each identity lists which values they possess.

**Example -- Departments:**

```json
{
  "name": "department",
  "rule": "anyOf",
  "values": ["engineering", "finance", "legal", "hr", "executive"]
}
```

Identity claims for this attribute:

```json
{
  "alice": { "department": ["engineering", "executive"] },
  "bob":   { "department": ["engineering"] },
  "carol": { "department": ["finance", "legal"] },
  "dave":  { "department": ["hr"] }
}
```

**Access scenarios:**

| Data tagged with | alice | bob | carol | dave |
|------------------|:-----:|:---:|:-----:|:----:|
| `[engineering]` | Yes | Yes | No | No |
| `[engineering, finance]` | Yes | Yes | Yes | No |
| `[executive]` | Yes | No | No | No |
| `[hr, legal]` | No | No | Yes | Yes |

**Key points:**
- Like allOf, the claim must be an array: `"department": ["engineering"]`, not `"department": "engineering"`.
- One matching value is enough. The user does not need all of them.
- An identity with no claim for an anyOf attribute cannot access any data tagged with that attribute.

---

## 5. Identity Reference

Each key in the `identities` map is a username. The value is a flat JSON object containing attribute claims and optional reserved fields.

### Username as the Key

```json
{
  "identities": {
    "alice": { ... },
    "bob": { ... },
    "svc-account": { ... }
  }
}
```

The username serves as the primary identifier throughout the system. It becomes the JWT `sub` claim, the basis for derived credentials, and the label used in audit logs.

### Claims Map to Attributes

Every non-reserved key in an identity object is treated as an attribute claim. The key must match the `name` of an attribute defined in the `attributes` array.

```json
{
  "attributes": [
    { "name": "clearance", "rule": "hierarchy", "values": ["ts", "s", "c"] },
    { "name": "groups", "rule": "allOf", "values": ["alpha", "bravo"] }
  ],
  "identities": {
    "alice": {
      "clearance": "ts",
      "groups": ["alpha", "bravo"]
    }
  }
}
```

Here `clearance` and `groups` are claims because they match attribute names. The system validates that:

- `"clearance": "ts"` is a scalar string (correct for hierarchy) and `ts` is in the attribute's values.
- `"groups": ["alpha", "bravo"]` is a string array (correct for allOf) and both `alpha` and `bravo` are in the attribute's values.

### Scalar vs. Array Claims

The expected type of a claim value is determined by the attribute's rule:

| Attribute Rule | Expected Claim Type | Example |
|----------------|--------------------:|---------|
| `hierarchy` | Scalar string | `"clearance": "secret"` |
| `allOf` | Array of strings | `"compliance": ["hipaa", "sox"]` |
| `anyOf` | Array of strings | `"department": ["engineering"]` |

Using the wrong type causes a validation error. A hierarchy claim cannot be an array. An allOf/anyOf claim cannot be a scalar string.

### Reserved Fields

Four field names are reserved and are never treated as attribute claims:

| Field | Type | Default | Purpose |
|-------|------|---------|---------|
| `admin` | boolean | `false` | Grants the admin role on the platform |
| `password` | string | `{username}-secret` | Password for the `password` grant type |
| `client_id` | string | `{username}-client` | OAuth2 client ID for `client_credentials` grant |
| `client_secret` | string | `{username}-secret` | OAuth2 client secret for `client_credentials` grant |

These fields are case-sensitive. `Admin` and `PASSWORD` are not reserved -- they would be treated as claim keys (and likely fail validation unless you defined matching attributes).

### Default Derivation Rules for Credentials

If you omit the reserved fields, the system derives credentials from the username:

| Username | password | client_id | client_secret |
|----------|----------|-----------|---------------|
| `alice` | `alice-secret` | `alice-client` | `alice-secret` |
| `bob` | `bob-secret` | `bob-client` | `bob-secret` |
| `svc-ingest` | `svc-ingest-secret` | `svc-ingest-client` | `svc-ingest-secret` |

This means for most development and testing scenarios, you never need to specify credentials. The defaults are deterministic and predictable.

### Full Annotated Identity Example

```json
{
  "identities": {
    "alice": {
      "admin": true,
      "classification": "top-secret",
      "compliance": ["hipaa", "sox", "gdpr"],
      "department": ["engineering", "executive"]
    },

    "bob": {
      "classification": "secret",
      "department": ["engineering"]
    },

    "service-account": {
      "classification": "confidential",
      "compliance": ["hipaa"],
      "department": ["engineering"],
      "password": "svc-strong-password",
      "client_id": "svc-app",
      "client_secret": "svc-app-secret"
    }
  }
}
```

- **alice**: Admin user with top-secret clearance, full compliance certs, member of engineering and executive. Credentials are derived: password `alice-secret`, client ID `alice-client`, client secret `alice-secret`.
- **bob**: Regular user with secret clearance, engineering only. No compliance certs. Credentials derived from username.
- **service-account**: Non-admin with explicit credential overrides. Uses custom client ID and secret for programmatic access.

---

## 6. Auto-Derivation (What the System Creates)

When TDFLite boots from a sealed policy bundle, it automatically provisions the OpenTDF platform database. You define attributes and identities; the system derives everything else.

### Subject Mappings

For every attribute value, the system creates a subject mapping that connects JWT claims to attribute values. This is the bridge between "who you are" (identity claims in your JWT) and "what you can access" (attribute values tagged on data).

**Concrete example.** Given this attribute:

```json
{
  "name": "classification",
  "rule": "hierarchy",
  "values": ["top-secret", "secret", "confidential"]
}
```

The system creates three subject mappings:

| Attribute Value | Selector | Operator | Matched Value |
|-----------------|----------|----------|---------------|
| `top-secret` | `.classification` | IN | `["top-secret"]` |
| `secret` | `.classification` | IN | `["secret"]` |
| `confidential` | `.classification` | IN | `["confidential"]` |

### Selectors

The selector is a JSONPath-like expression evaluated against the user's JWT claims:

- **Hierarchy attributes** use `.{name}` -- a dot-notation selector for a scalar claim. Example: `.classification` extracts the string value of the `classification` claim from the JWT.
- **allOf/anyOf attributes** use `.{name}[]` -- an array selector that iterates over the claim array. Example: `.department[]` extracts each element from the `department` claim array.

### Operators

All auto-generated subject mappings use the `IN` operator. This checks whether the extracted claim value is in the set of matched values for that mapping.

### Actions

Every subject mapping is created with the default actions `["read", "create"]`, unless overridden via the `options.default_actions` field.

### Namespace

All attributes are created under the bundle's effective namespace. If no namespace is specified, `tdflite.local` is used. The resulting attribute FQNs follow the pattern:

```
https://{namespace}/attr/{attribute_name}/value/{value}
```

For example, with namespace `tdflite.local` and attribute `classification` with value `top-secret`:

```
https://tdflite.local/attr/classification/value/top-secret
```

### Built-in Service Accounts

In addition to the identities you define, the system creates two built-in service accounts:

| Account | Client ID | Client Secret | Role | Purpose |
|---------|-----------|---------------|------|---------|
| Admin | `opentdf` | `secret` | Platform admin | Internal platform operations, policy provisioning |
| SDK | `opentdf-sdk` | `secret` | SDK client | Default client for encrypt/decrypt via OpenTDF SDKs |

These are required by the OpenTDF platform and are always created regardless of what you define in the policy bundle.

### Full Derivation Example

Given this policy fragment:

```json
{
  "attributes": [
    { "name": "clearance", "rule": "hierarchy", "values": ["ts", "s", "c"] },
    { "name": "teams", "rule": "anyOf", "values": ["alpha", "bravo"] }
  ],
  "identities": {
    "alice": { "clearance": "ts", "teams": ["alpha", "bravo"] },
    "bob": { "clearance": "s", "teams": ["alpha"] }
  }
}
```

The system provisions:

1. **Namespace:** `tdflite.local`
2. **Attributes:**
   - `https://tdflite.local/attr/clearance` (hierarchy) with values `ts`, `s`, `c`
   - `https://tdflite.local/attr/teams` (anyOf) with values `alpha`, `bravo`
3. **Subject mappings** (5 total):
   - `.clearance` IN `["ts"]` maps to attribute value `ts` with actions `[read, create]`
   - `.clearance` IN `["s"]` maps to attribute value `s` with actions `[read, create]`
   - `.clearance` IN `["c"]` maps to attribute value `c` with actions `[read, create]`
   - `.teams[]` IN `["alpha"]` maps to attribute value `alpha` with actions `[read, create]`
   - `.teams[]` IN `["bravo"]` maps to attribute value `bravo` with actions `[read, create]`
4. **Identities:**
   - `alice` -- password: `alice-secret`, client ID: `alice-client`, client secret: `alice-secret`
   - `bob` -- password: `bob-secret`, client ID: `bob-client`, client secret: `bob-secret`
   - `opentdf` (admin) -- client ID: `opentdf`, client secret: `secret`
   - `opentdf-sdk` (SDK) -- client ID: `opentdf-sdk`, client secret: `secret`

---

## 7. The Sealed File

Sealing adds two fields to the bundle: `sealed` and `signature`. The rest of the file is unchanged.

### What Gets Added

**The `sealed` section** contains three fields:

| Field | Content | Purpose |
|-------|---------|---------|
| `kas_keys` | age-encrypted string | RSA-2048 and EC P-256 private keys for the Key Access Server, encrypted with your SSH public key |
| `idp_key` | age-encrypted string | IdP JWT signing key, encrypted with your SSH public key |
| `fingerprint` | SSH key fingerprint (e.g., `SHA256:xxxx`) | Identifies which SSH key can unseal this bundle |

**The `signature` field** is a base64-encoded signature computed over all other fields (attributes, identities, options, sealed section). It covers the entire bundle so that any modification -- even to the plaintext policy -- is detectable.

### Policy Stays Readable

A critical design choice: the policy itself is not encrypted. Only the cryptographic keys are encrypted. This means:

- You can read the sealed file to see exactly what policy is in effect.
- You can diff two sealed files to see what changed between policy versions.
- You can review policy changes in pull requests.
- Audit and compliance teams can inspect the policy without needing the SSH key.

The SSH key is only needed to boot the platform, not to understand the policy.

### Full Annotated Sealed Example

```json
{
  "version": 1,
  "namespace": "tdflite.local",

  "attributes": [
    {
      "name": "classification_level",
      "rule": "hierarchy",
      "values": ["TOP_SECRET", "SECRET", "CONFIDENTIAL", "UNCLASSIFIED"]
    },
    {
      "name": "sci_control_system",
      "rule": "allOf",
      "values": ["SI", "HCS", "TK"]
    },
    {
      "name": "releasable_to",
      "rule": "allOf",
      "values": ["USA", "GBR", "CAN", "AUS", "NZL"]
    }
  ],

  "identities": {
    "alice": {
      "classification_level": "TOP_SECRET",
      "sci_control_system": ["SI", "HCS", "TK"],
      "releasable_to": ["USA", "GBR", "CAN", "AUS", "NZL"]
    },
    "bob": {
      "classification_level": "TOP_SECRET",
      "releasable_to": ["USA"]
    },
    "carol": {
      "classification_level": "SECRET",
      "releasable_to": ["USA", "GBR", "CAN", "AUS", "NZL"]
    },
    "dave": {
      "classification_level": "CONFIDENTIAL",
      "releasable_to": ["USA"]
    },
    "eve": {
      "classification_level": "UNCLASSIFIED"
    }
  },

  "sealed": {
    "kas_keys": "age1placeholder-encrypted-kas-keys-would-go-here",
    "idp_key": "age1placeholder-encrypted-idp-key-would-go-here",
    "fingerprint": "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
  },

  "signature": "PLACEHOLDER-base64-ed25519-signature-would-go-here"
}
```

**Observations:**

- The `attributes` and `identities` sections are identical to the plain policy file. They are not encrypted or obfuscated.
- The `sealed` section is the only new content. Its values are opaque encrypted blobs.
- The `fingerprint` tells you which SSH key sealed this file. If you have multiple SSH keys, this tells you which one to use.
- The `signature` covers everything. Change a single character anywhere in the file, and the signature verification will fail at boot time.

---

## 8. Validation Rules

### On Seal

When you run `tdflite seal`, the following validations are performed before any keys are generated or encrypted:

**Structural requirements:**
- At least one attribute must be defined.
- At least one identity must be defined.
- Every attribute must have a non-empty `name`.
- Every attribute must have a valid `rule` (`hierarchy`, `allOf`, or `anyOf`).
- Every attribute must have at least one value.
- No attribute values may be empty strings.
- No duplicate attribute names.

**Identity-attribute cross-validation:**
- Every claim key in every identity must match the name of a defined attribute.
- Reserved keys (`admin`, `password`, `client_id`, `client_secret`) are not treated as claims.

**Type enforcement by rule:**

| Attribute Rule | Required Claim Type | Validation |
|----------------|---------------------|------------|
| `hierarchy` | Scalar string | The value must be one of the attribute's defined values |
| `allOf` | Array of strings | Every element must be one of the attribute's defined values |
| `anyOf` | Array of strings | Every element must be one of the attribute's defined values |

**Example validation errors:**

```
policy bundle validation failed:
  - at least one attribute is required
  - identity "alice": claim "clearance" does not match any attribute
  - identity "bob": claim "level" must be a string (hierarchy attribute)
  - identity "carol": claim "groups" value "invalid" is not in attribute values [eng ops]
  - attribute "dept": duplicate name
```

### On Boot (Serve)

When TDFLite boots from a sealed bundle, additional checks are performed:

1. **Signature verification** -- The signature is verified against the bundle contents. If the file has been modified since sealing, the platform refuses to start.
2. **Key decryption** -- The encrypted keys in the `sealed` section are decrypted using the provided SSH private key. If the wrong key is provided, decryption fails and the platform refuses to start.
3. **Schema version check** -- The bundle version must be a supported version (currently only `1`).

---

## 9. Workflow

### Author

Create a plain policy file:

```bash
tdflite policy init > policy.json
# Or write it by hand -- it's just JSON
```

Edit `policy.json` in any text editor. Define your attributes and identities. Commit it to version control.

### Seal

Lock the policy to your SSH key:

```bash
tdflite seal --policy policy.json --ssh-key ~/.ssh/id_ed25519
# Produces: policy.sealed.json
```

This generates fresh KAS keys, encrypts them with your SSH public key, signs the bundle, and writes the sealed file.

### Boot

Start the platform:

```bash
tdflite serve --policy policy.sealed.json --key ~/.ssh/id_ed25519
```

The platform unseals the bundle, provisions all attributes, identities, and subject mappings, and starts serving.

### Update

To change the policy:

```bash
# 1. Edit the plain policy
vim policy.json

# 2. Re-seal (generates new keys and signature)
tdflite seal --policy policy.json --ssh-key ~/.ssh/id_ed25519

# 3. Restart the platform
tdflite serve --policy policy.sealed.json --key ~/.ssh/id_ed25519
```

### Key Rotation (Rebind)

To re-encrypt the sealed bundle with a different SSH key without changing the policy or regenerating KAS keys:

```bash
tdflite policy rebind \
  --policy policy.sealed.json \
  --old-key ~/.ssh/id_ed25519_old \
  --new-key ~/.ssh/id_ed25519_new
```

This decrypts the existing keys with the old SSH key and re-encrypts them with the new SSH key. The KAS keys themselves do not change, so existing encrypted data remains accessible.

### Full Lifecycle Diagram

```
  Author            Seal                Boot                Update
    |                 |                   |                    |
    v                 v                   v                    v
policy.json ----> tdflite seal ----> tdflite serve ----> edit policy.json
 (you write)     (encrypts keys,    (decrypts keys,      (re-seal, restart)
                  signs bundle)      provisions policy,
                                     starts platform)

  Rebind (key rotation)
    |
    v
policy.sealed.json ----> tdflite policy rebind ----> policy.sealed.json
 (old SSH key)          (decrypt with old key,       (new SSH key)
                         re-encrypt with new key)
```

---

## 10. Options Reference

The `options` section is entirely optional. Omit it to use defaults.

```json
{
  "options": {
    "token_ttl": "30m",
    "default_actions": ["read", "create", "delete"]
  }
}
```

### token_ttl

**Type:** String (Go duration format)
**Default:** Platform default
**Examples:** `"5m"`, `"30m"`, `"1h"`, `"24h"`

Overrides the time-to-live for tokens issued by the built-in IdP. Shorter values are more secure (tokens expire faster) but require more frequent re-authentication. Longer values are more convenient for development.

Use this when:
- You want shorter token lifetimes for security-sensitive deployments.
- You want longer token lifetimes for development convenience.

### default_actions

**Type:** Array of strings
**Default:** `["read", "create"]`

Overrides the actions applied to all auto-generated subject mappings. These actions determine what operations users can perform on data matching their attribute claims.

Use this when:
- You need to restrict users to read-only access by default: `["read"]`
- You need to grant additional capabilities: `["read", "create", "delete"]`

When to rely on defaults: Most use cases only need `read` and `create`. If your access model does not differentiate on action types, leave this unset.

---

## 11. Schema Reference

### Top-Level Bundle

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `version` | integer | No | `1` | Schema version |
| `namespace` | string | No | `tdflite.local` | DNS-style namespace for attribute FQNs |
| `attributes` | array of Attribute | Yes | -- | Attribute definitions |
| `identities` | map of string to Identity | Yes | -- | User/service account definitions |
| `options` | Options | No | `null` | Optional overrides |
| `sealed` | Sealed | No | `null` | Present only in sealed bundles |
| `signature` | string | No | `""` | Present only in sealed bundles |

### Attribute

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Attribute identifier; must be unique within the bundle |
| `rule` | string | Yes | One of `hierarchy`, `allOf`, `anyOf` |
| `values` | array of strings | Yes | Allowed values; order matters for hierarchy (first = highest) |

### Identity

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `admin` | boolean | No | `false` | Grants platform admin role |
| `password` | string | No | `{username}-secret` | Password for password grant |
| `client_id` | string | No | `{username}-client` | OAuth2 client ID |
| `client_secret` | string | No | `{username}-secret` | OAuth2 client secret |
| *{attribute_name}* | string or array of strings | No | -- | Attribute claim; type depends on attribute rule |

### Options

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `token_ttl` | string | No | Platform default | Token time-to-live (Go duration) |
| `default_actions` | array of strings | No | `["read", "create"]` | Actions for subject mappings |

### Sealed

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `kas_keys` | string | Yes | age-encrypted RSA + EC private keys |
| `idp_key` | string | Yes | age-encrypted IdP signing key |
| `fingerprint` | string | SSH mode only | SSH key fingerprint (e.g., `SHA256:xxxx`). Empty in passphrase mode |
| `method` | string | No | `"ssh"` (default) or `"passphrase"` |

---

## 12. FAQ / Gotchas

### What if I lose my SSH key?

You need to re-seal the policy with a new SSH key. The KAS keys in the existing sealed bundle are irrecoverable without the original SSH key. Since re-sealing generates new KAS keys, any data encrypted under the old KAS keys will no longer be decryptable. This is by design -- the SSH key is the root of trust.

**Mitigation:** Back up your SSH key. If you need disaster recovery, keep a copy of the SSH private key in a secure, offline location.

### Can multiple people unseal the same bundle?

Not yet. Currently, a sealed bundle is locked to a single SSH key. Multi-party unsealing (encrypting the KAS keys to multiple SSH public keys) is a planned feature.

**Workaround:** Share the SSH private key among authorized operators via a secrets manager, or designate a single operator who manages the platform lifecycle.

### What about key rotation?

Use the `rebind` command to re-encrypt the sealed bundle with a new SSH key:

```bash
tdflite policy rebind --policy policy.sealed.json --old-key ~/.ssh/old --new-key ~/.ssh/new
```

This changes which SSH key can boot the platform without regenerating KAS keys. Existing encrypted data remains accessible.

To rotate the KAS keys themselves, re-seal the policy from the plain file. This generates fresh KAS keys, meaning previously encrypted data will need to be re-encrypted.

### Can I use RSA SSH keys?

Yes. Both Ed25519 and RSA SSH keys are supported for sealing and unsealing. The age encryption library handles both key types transparently.

### Can I seal with a passphrase instead of an SSH key?

Yes. Pass `--passphrase` instead of `--ssh-key` when sealing. The KAS keys are encrypted with a key derived from your passphrase via scrypt (using age's built-in passphrase encryption). You will be prompted for the passphrase on every boot.

SSH key mode is recommended for production because:
- No password to type or manage on every restart.
- SSH key agents handle key access transparently.
- SSH key rotation is well-understood operationally.

Passphrase mode is useful for:
- Quick demos where you don't want to deal with SSH keys.
- Shared environments where distributing an SSH key is impractical.
- CI/CD pipelines where a passphrase can be injected from a secrets manager.

### Is the policy file encrypted?

No. Only the KAS and IdP keys in the `sealed` section are encrypted. The `attributes`, `identities`, and `options` sections remain plaintext JSON. This is intentional:

- Policy should be auditable without requiring the SSH key.
- Policy changes should be visible in version control diffs.
- Compliance reviewers should be able to inspect access control rules without operational access.

If your policy itself contains sensitive information (e.g., the existence of certain users or attribute values is classified), you should protect the sealed file at the filesystem or repository level using standard access controls.

### What happens if I modify the sealed file?

The platform refuses to start. The `signature` field covers the entire bundle. Any modification -- adding a user, changing a clearance level, altering an attribute value, or even changing whitespace in the sealed keys -- will cause signature verification to fail.

To make changes, edit the plain policy file and re-seal.

### Can I use the same policy across multiple instances?

Yes. The sealed file is portable. Any machine with the sealed file and the corresponding SSH private key can boot a TDFLite instance with identical policy. This is useful for:

- Staging and production environments with the same policy.
- Disaster recovery on a different machine.
- Horizontal scaling (though each instance needs its own embedded PostgreSQL).

### What is the namespace used for?

The namespace becomes part of attribute fully-qualified names (FQNs). For example, with namespace `acme.example.com` and attribute `classification`, the FQN for value `secret` is:

```
https://acme.example.com/attr/classification/value/secret
```

This is the identifier stored inside encrypted TDF objects. If you change the namespace after encrypting data, the old data references the old namespace and new attribute definitions will not match. Use a stable namespace.

### Why are identities not in a separate file?

The single-file design is deliberate. Keeping attributes and identities together means:

- The bundle is self-contained. No dangling references.
- Validation can cross-check everything at seal time.
- One file in version control, one review process, one approval.
- No possibility of deploying mismatched attribute definitions and identity assignments.

### What is the minimum valid policy?

One attribute with one value and one identity with one claim:

```json
{
  "attributes": [
    { "name": "access", "rule": "anyOf", "values": ["granted"] }
  ],
  "identities": {
    "user": { "access": ["granted"] }
  }
}
```

Everything else -- version, namespace, options, credentials -- has defaults.
