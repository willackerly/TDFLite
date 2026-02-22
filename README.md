# TDFLite

**The full OpenTDF platform in a single binary. No Docker. No Keycloak. No infrastructure.**

---

Data sovereignty and zero-trust access control shouldn't require a weekend of DevOps.
The [OpenTDF platform](https://github.com/opentdf/platform) is powerful -- attribute-based
access control, key management, policy enforcement -- but deploying it means orchestrating
PostgreSQL, Keycloak, config files, provisioning scripts, and Docker Compose. TDFLite
eliminates all of that. One binary. One policy file. Your SSH key. That's it.

## Quick Start

```bash
# 1. Write a policy file (who gets access to what)
cat > policy.json << 'EOF'
{
  "attributes": [
    { "name": "classification", "rule": "hierarchy", "values": ["top-secret", "secret", "confidential"] }
  ],
  "identities": {
    "alice": { "classification": "top-secret", "admin": true },
    "bob":   { "classification": "confidential" }
  }
}
EOF

# 2. Seal it with your SSH key (encrypts KAS keys, signs the file)
tdflite seal --policy policy.json --ssh-key ~/.ssh/id_ed25519

# 3. Boot the platform
tdflite serve --policy policy.sealed.json --key ~/.ssh/id_ed25519

# 4. Encrypt data (alice can decrypt; bob cannot -- his clearance is too low)
echo "launch codes" | otdfctl encrypt --attr classification=top-secret

# 5. Decrypt as alice
otdfctl decrypt < encrypted.tdf
```

Alice has `top-secret` clearance. Bob has `confidential`. The hierarchy rule means
Alice can access everything at or below her level, but Bob is locked out of anything
above `confidential`. This is the entire access control model -- defined in five lines
of JSON, enforced by the full OpenTDF platform.

---

## The Sealed Policy Bundle

This is the core idea. Everything your platform needs to run lives in a single JSON file.

### What you write: `policy.json`

A plain, human-readable policy file. No YAML, no Helm charts, no provisioning scripts.

```json
{
  "attributes": [
    {
      "name": "classification",
      "rule": "hierarchy",
      "values": ["top-secret", "secret", "confidential", "unclassified"]
    },
    {
      "name": "department",
      "rule": "anyOf",
      "values": ["engineering", "finance", "legal", "hr"]
    },
    {
      "name": "compliance",
      "rule": "allOf",
      "values": ["hipaa", "sox", "gdpr"]
    }
  ],

  "identities": {
    "alice": {
      "admin": true,
      "classification": "top-secret",
      "department": ["engineering", "finance"],
      "compliance": ["hipaa", "sox", "gdpr"]
    },
    "bob": {
      "classification": "secret",
      "department": ["engineering"],
      "compliance": ["hipaa"]
    },
    "auditor": {
      "classification": "confidential",
      "department": ["finance", "legal"],
      "compliance": ["sox", "gdpr"]
    }
  }
}
```

That's the entire policy. Three attributes. Three users. Every access decision the
platform will ever make is derived from this file.

### What happens when you seal it

```bash
tdflite seal --policy policy.json --ssh-key ~/.ssh/id_ed25519
```

The `seal` command:

1. **Validates** the policy -- every identity claim must reference a defined attribute,
   hierarchy claims must be scalar strings, allOf/anyOf claims must be arrays, values
   must exist in the attribute definition
2. **Generates** KAS key pairs (RSA-2048 + EC P-256) and an IdP signing key
3. **Encrypts** all private keys with your SSH public key using age encryption
4. **Signs** the entire bundle so any modification is detectable
5. **Writes** `policy.sealed.json` -- a single file containing policy + encrypted keys + signature

The sealed file looks like this:

```json
{
  "version": 1,
  "namespace": "tdflite.local",
  "attributes": [ ... ],
  "identities": { ... },
  "sealed": {
    "kas_keys": "age-encrypted RSA + EC private keys",
    "idp_key": "age-encrypted IdP signing key",
    "fingerprint": "SHA256:your-ssh-key-fingerprint"
  },
  "signature": "base64-encoded-signature"
}
```

### Why this matters

**Your SSH key is the root of trust.** The KAS private keys -- the keys that actually
decrypt protected data -- are encrypted with your SSH public key. Without the
corresponding private key, the sealed bundle is inert. No one can start the platform.
No one can decrypt data. Not even someone with root access to the server, unless they
also have your SSH key.

**Or use a passphrase.** For quick demos and environments where SSH keys are
impractical, seal with `--passphrase` instead. The keys are encrypted with a
passphrase-derived key (scrypt via age). SSH key mode is recommended for production;
passphrase mode gets you started in seconds.

**The file is tamper-evident.** The signature covers every field. Change a single
attribute value, add a user, modify a clearance level -- the signature breaks and
the platform refuses to start. You get a complete audit trail through version control.

**The file is diffable.** It's JSON. Put it in Git. Review policy changes in pull
requests. See exactly what changed, when, and who approved it. Policy-as-code,
for real this time.

### The lifecycle

```
  Author           Seal               Boot                Update
    |                |                  |                    |
    v                v                  v                    v
policy.json ---> tdflite seal ---> tdflite serve ---> edit policy.json
(you write)     (encrypts keys,   (decrypts keys,     (repeat)
                 signs bundle)     provisions policy,
                                   starts platform)
```

Every time you update the policy, you re-seal and restart. The platform reads the
sealed bundle, decrypts the keys with your SSH key, provisions attributes and
identity mappings into the database, and starts serving. No manual provisioning.
No API calls. No scripts.

---

## What It Replaces

| Traditional OpenTDF | TDFLite |
|---|---|
| `docker-compose.yaml` (Postgres, Keycloak, platform) | `policy.sealed.json` |
| `keycloak-realm.json` (realm config, client IDs, roles) | Part of `policy.sealed.json` |
| `opentdf.yaml` (platform config, DB creds, auth settings) | Auto-generated at boot |
| Keycloak admin provisioning scripts | Not needed |
| KAS key generation + distribution scripts | Sealed in the bundle |
| Identity provider setup + client registration | Built-in IdP, identities in the bundle |
| TLS certificate management | Optional (dev mode works without TLS) |
| **7+ files, 3 services, Docker required** | **1 file + 1 SSH key, no Docker** |

---

## How Attributes Work

TDFLite supports three attribute rules that determine how access decisions are made:

### Hierarchy

Values are ordered by rank. First value = highest clearance. A user with a given level
can access data tagged at that level or below.

```json
{ "name": "classification", "rule": "hierarchy", "values": ["top-secret", "secret", "confidential"] }
```

A user with `"classification": "secret"` can access `secret` and `confidential` data,
but not `top-secret`.

### allOf

The user must possess **every** value tagged on the data. Used for compliance
requirements where all certifications are mandatory.

```json
{ "name": "compliance", "rule": "allOf", "values": ["hipaa", "sox", "gdpr"] }
```

If data is tagged with `compliance=[hipaa, sox]`, the user must have both `hipaa` and
`sox` in their claims to access it.

### anyOf

The user must possess **at least one** value tagged on the data. Used for broad
department or role-based access.

```json
{ "name": "department", "rule": "anyOf", "values": ["engineering", "finance", "legal"] }
```

If data is tagged with `department=[engineering, finance]`, a user with either
`engineering` or `finance` can access it.

---

## Architecture

TDFLite is a thin wrapper around the real OpenTDF platform. It does not reimplement
any platform functionality. It starts embedded infrastructure, generates config, and
calls the platform's own `server.Start()`.

```
                    +-----------------------------------------+
                    |          tdflite binary (Go)            |
                    |                                         |
                    |  1. Unseal policy bundle (SSH key)      |
                    |  2. Start embedded PostgreSQL (:15432)  |
                    |  3. Start built-in OIDC IdP  (:15433)  |
                    |  4. Provision policy into database      |
                    |  5. Start OpenTDF platform   (:8080)    |
                    |                                         |
                    |  Wraps:                                 |
                    |    github.com/opentdf/platform/service  |
                    +-----------+---------------+-------------+
                                |               |
                                v               v
                        +------------+    +------------+
                        | embedded   |    |  idplite   |
                        | PostgreSQL |    |  OIDC IdP  |
                        |   :15432   |    |   :15433   |
                        +------------+    +------------+
```

**Embedded PostgreSQL** -- A real PostgreSQL instance (v16), downloaded and cached
on first run. All 39+ OpenTDF database migrations run automatically. Data persists
between restarts in the `data/` directory. No Docker involved.

**idplite** -- A minimal OIDC-compliant identity provider (~550 lines of Go) that
serves OpenID Connect discovery, JWKS, and token endpoints. Supports
`client_credentials` and `password` grants. Issues standard JWTs that the OpenTDF
platform validates using its normal auth pipeline. No Keycloak involved.

**The platform itself** -- Imported as a Go module dependency. TDFLite calls
`server.Start()` with config pointing at the embedded Postgres and idplite. All 17
OpenTDF services run: policy, attributes, subject mappings, KAS, entity resolution,
authorization, and more. Full platform. Not a subset.

---

## Status

**Phase 0: Wrap-and-Shim** -- Complete. The single binary boots embedded PostgreSQL,
idplite, and the full OpenTDF platform. End-to-end verified: encrypt and decrypt
operations work, all 17 services respond, 33+ unit tests pass.

**Sealed Policy Bundle** -- Schema defined, validation implemented, seal/unseal and
boot-time provisioning in active development.

### Roadmap

| Phase | Description | Status |
|-------|-------------|--------|
| Phase 0 | Wrap-and-shim: embedded Postgres + idplite + `server.Start()` | Complete |
| Phase 0.5 | Sealed policy bundle: single-file policy + encrypted keys | In progress |
| Phase 1 | SQLite shim: replace embedded Postgres with pure-Go SQLite | Future |
| Phase 2 | In-memory mode: ephemeral instances for testing and CI | Future |

---

## Building

Requires Go 1.23+.

```bash
git clone https://github.com/willackerly/TDFLite.git
cd TDFLite

go build -o tdflite ./cmd/tdflite

./tdflite version
./tdflite serve --port 9090
```

### Flags

```
tdflite serve [flags]

  --policy      Path to sealed policy bundle (default: none, uses legacy config)
  --key         Path to SSH private key for unsealing (default: ~/.ssh/id_ed25519)
  --config      Path to OpenTDF YAML config file (default: auto-generated)
  --data-dir    Directory for runtime state (default: ./data)
  --port        Platform server port (default: 8080)
  --pg-port     Embedded PostgreSQL port (default: 15432)
  --idp-port    Built-in OIDC IdP port (default: 15433)
```

### Environment Variables

```bash
TDFLITE_CONFIG=./config/tdflite.yaml   # Config file path
TDFLITE_PORT=8080                       # Server port
TDFLITE_DATA_DIR=./data                 # State persistence directory
TDFLITE_LOG_LEVEL=info                  # debug, info, warn, error
```

---

## Project Structure

```
cmd/tdflite/           Main binary: orchestrates startup sequence
internal/
  policybundle/        Sealed policy bundle schema + validation
  idplite/             Built-in OIDC IdP (discovery, JWKS, tokens)
  embeddedpg/          Embedded PostgreSQL lifecycle wrapper
  keygen/              KAS key pair generation (RSA + EC)
  loader/              OpenTDF config generator
config/                Default configuration
data/                  Runtime state (keys, Postgres data, identities)
docs/                  Architecture documentation
```

---

## License

[Apache 2.0](LICENSE)

---

Built on the [OpenTDF platform](https://github.com/opentdf/platform).
TDFLite wraps it -- every access decision, every key operation, every policy
evaluation runs through the real platform code. Nothing reimplemented. Nothing
watered down.
