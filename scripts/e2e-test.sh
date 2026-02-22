#!/usr/bin/env bash
# e2e-test.sh — End-to-end encrypt/decrypt classification tests
#
# Tests the full TDF lifecycle: encrypt with classification attributes,
# then verify that users at appropriate clearance levels can (or cannot)
# decrypt the data.
#
# Prerequisites:
#   1. TDFLite running (./tdflite serve --port 9090)
#   2. Policy provisioned (bash scripts/provision.sh --host http://localhost:9090)
#   3. otdfctl installed (~/go/bin/otdfctl)
#
# Usage:
#   bash scripts/e2e-test.sh [--host http://localhost:9090]

set -euo pipefail

# --- Defaults ---
PLATFORM_HOST="${PLATFORM_HOST:-http://localhost:9090}"
OTDFCTL="${OTDFCTL:-$(command -v otdfctl 2>/dev/null || echo "$HOME/go/bin/otdfctl")}"
TMPDIR="${TMPDIR:-/tmp}/tdflite-e2e-$$"
NAMESPACE="tdflite.local"

# Track results
PASS=0
FAIL=0
TESTS=()

# --- Parse args ---
while [[ $# -gt 0 ]]; do
  case $1 in
    --host) PLATFORM_HOST="$2"; shift 2 ;;
    *)      echo "Unknown arg: $1"; exit 1 ;;
  esac
done

echo "=== TDFLite E2E Classification Tests ==="
echo "Platform: $PLATFORM_HOST"
echo "otdfctl:  $OTDFCTL"
echo "Temp dir: $TMPDIR"
echo ""

# --- Preflight ---
if [[ ! -x "$OTDFCTL" ]]; then
  echo "FAIL: otdfctl not found at $OTDFCTL"
  echo "  Install: go install github.com/opentdf/otdfctl@latest"
  exit 1
fi

mkdir -p "$TMPDIR"
trap 'rm -rf "$TMPDIR"' EXIT

# --- Helpers ---

# creds_json returns a JSON credentials string for otdfctl --with-client-creds
creds_json() {
  local client_id="$1"
  local client_secret="$2"
  echo "{\"clientId\":\"${client_id}\",\"clientSecret\":\"${client_secret}\"}"
}

# encrypt_file creates a TDF file with given attributes, using the SDK service account
encrypt_file() {
  local output_file="$1"
  local plaintext="$2"
  shift 2
  # Remaining args are --attr flags
  local attr_args=()
  for attr in "$@"; do
    attr_args+=(--attr "$attr")
  done

  echo "$plaintext" | GRPC_ENFORCE_ALPN_ENABLED=false "$OTDFCTL" encrypt \
    --host "$PLATFORM_HOST" \
    --tls-no-verify \
    --with-client-creds "$(creds_json opentdf-sdk secret)" \
    "${attr_args[@]}" \
    -o "$output_file" 2>&1
}

# try_decrypt attempts to decrypt a TDF file as a given user
# Returns 0 on success, 1 on failure
try_decrypt() {
  local tdf_file="$1"
  local client_id="$2"
  local client_secret="$3"
  local output_file="${TMPDIR}/decrypt-output-$$.txt"

  GRPC_ENFORCE_ALPN_ENABLED=false "$OTDFCTL" decrypt \
    --host "$PLATFORM_HOST" \
    --tls-no-verify \
    --with-client-creds "$(creds_json "$client_id" "$client_secret")" \
    "$tdf_file" \
    -o "$output_file" 2>&1 && {
    cat "$output_file"
    rm -f "$output_file"
    return 0
  } || {
    rm -f "$output_file"
    return 1
  }
}

# test_positive: expect decrypt to succeed
test_positive() {
  local description="$1"
  local tdf_file="$2"
  local client_id="$3"
  local client_secret="$4"

  printf "  %-60s " "$description"
  if try_decrypt "$tdf_file" "$client_id" "$client_secret" > /dev/null 2>&1; then
    echo "PASS"
    PASS=$((PASS + 1))
    TESTS+=("PASS: $description")
  else
    echo "FAIL (expected decrypt to succeed)"
    FAIL=$((FAIL + 1))
    TESTS+=("FAIL: $description")
  fi
}

# test_negative: expect decrypt to fail
test_negative() {
  local description="$1"
  local tdf_file="$2"
  local client_id="$3"
  local client_secret="$4"

  printf "  %-60s " "$description"
  if try_decrypt "$tdf_file" "$client_id" "$client_secret" > /dev/null 2>&1; then
    echo "FAIL (expected decrypt to be denied)"
    FAIL=$((FAIL + 1))
    TESTS+=("FAIL: $description")
  else
    echo "PASS (correctly denied)"
    PASS=$((PASS + 1))
    TESTS+=("PASS: $description")
  fi
}

# --- Create test data ---
echo "--- Creating encrypted test data ---"
echo ""

# Attribute FQN format: https://<namespace>/attr/<name>/value/<value>
ATTR_BASE="https://${NAMESPACE}/attr"

echo "  Encrypting TOP_SECRET document..."
encrypt_file "$TMPDIR/ts.tdf" "TOP SECRET DATA - Eyes Only" \
  "${ATTR_BASE}/classification_level/value/top_secret"

echo "  Encrypting SECRET document..."
encrypt_file "$TMPDIR/s.tdf" "SECRET DATA - Limited Distribution" \
  "${ATTR_BASE}/classification_level/value/secret"

echo "  Encrypting CONFIDENTIAL document..."
encrypt_file "$TMPDIR/c.tdf" "CONFIDENTIAL DATA - Internal Use" \
  "${ATTR_BASE}/classification_level/value/confidential"

echo "  Encrypting UNCLASSIFIED document..."
encrypt_file "$TMPDIR/u.tdf" "UNCLASSIFIED DATA - Public Release" \
  "${ATTR_BASE}/classification_level/value/unclassified"

echo "  Encrypting TS/SCI document (requires SCI=SI)..."
encrypt_file "$TMPDIR/ts-sci.tdf" "TS/SCI DATA - Compartmented" \
  "${ATTR_BASE}/classification_level/value/top_secret" \
  "${ATTR_BASE}/sci_control_system/value/si"

echo "  Encrypting SECRET/REL USA document..."
encrypt_file "$TMPDIR/s-usa.tdf" "SECRET REL USA - US Only" \
  "${ATTR_BASE}/classification_level/value/secret" \
  "${ATTR_BASE}/releasable_to/value/usa"

echo "  Encrypting SECRET/REL FVEY document..."
encrypt_file "$TMPDIR/s-fvey.tdf" "SECRET REL FVEY - Five Eyes" \
  "${ATTR_BASE}/classification_level/value/secret" \
  "${ATTR_BASE}/releasable_to/value/usa" \
  "${ATTR_BASE}/releasable_to/value/gbr"

echo ""
echo "--- Running classification hierarchy tests ---"
echo ""

# === POSITIVE TESTS ===
echo "POSITIVE (should decrypt):"

# Alice (TS/SCI) can decrypt everything in the hierarchy
test_positive "Alice (TS/SCI) decrypts TOP_SECRET" \
  "$TMPDIR/ts.tdf" alice-client alice-secret

test_positive "Alice (TS/SCI) decrypts SECRET" \
  "$TMPDIR/s.tdf" alice-client alice-secret

test_positive "Alice (TS/SCI) decrypts CONFIDENTIAL" \
  "$TMPDIR/c.tdf" alice-client alice-secret

test_positive "Alice (TS/SCI) decrypts UNCLASSIFIED" \
  "$TMPDIR/u.tdf" alice-client alice-secret

# Bob (TS collateral, no SCI) can decrypt TS and below
test_positive "Bob (TS collateral) decrypts TOP_SECRET" \
  "$TMPDIR/ts.tdf" bob-client bob-secret

test_positive "Bob (TS collateral) decrypts SECRET" \
  "$TMPDIR/s.tdf" bob-client bob-secret

# Carol (S) can decrypt SECRET and below
test_positive "Carol (S) decrypts SECRET" \
  "$TMPDIR/s.tdf" carol-client carol-secret

test_positive "Carol (S) decrypts CONFIDENTIAL" \
  "$TMPDIR/c.tdf" carol-client carol-secret

test_positive "Carol (S) decrypts UNCLASSIFIED" \
  "$TMPDIR/u.tdf" carol-client carol-secret

# Dave (C) can decrypt CONFIDENTIAL and below
test_positive "Dave (C) decrypts CONFIDENTIAL" \
  "$TMPDIR/c.tdf" dave-client dave-secret

test_positive "Dave (C) decrypts UNCLASSIFIED" \
  "$TMPDIR/u.tdf" dave-client dave-secret

# Eve (U) can decrypt UNCLASSIFIED
test_positive "Eve (U) decrypts UNCLASSIFIED" \
  "$TMPDIR/u.tdf" eve-client eve-secret

# Alice (TS + SCI SI) can decrypt TS/SCI data
test_positive "Alice (TS/SCI) decrypts TS/SCI(SI)" \
  "$TMPDIR/ts-sci.tdf" alice-client alice-secret

echo ""
echo "NEGATIVE (should be denied):"

# === NEGATIVE TESTS ===

# Carol (S) cannot decrypt TOP_SECRET
test_negative "Carol (S) cannot decrypt TOP_SECRET" \
  "$TMPDIR/ts.tdf" carol-client carol-secret

# Dave (C) cannot decrypt SECRET
test_negative "Dave (C) cannot decrypt SECRET" \
  "$TMPDIR/s.tdf" dave-client dave-secret

# Dave (C) cannot decrypt TOP_SECRET
test_negative "Dave (C) cannot decrypt TOP_SECRET" \
  "$TMPDIR/ts.tdf" dave-client dave-secret

# Eve (U) cannot decrypt CONFIDENTIAL
test_negative "Eve (U) cannot decrypt CONFIDENTIAL" \
  "$TMPDIR/c.tdf" eve-client eve-secret

# Eve (U) cannot decrypt SECRET
test_negative "Eve (U) cannot decrypt SECRET" \
  "$TMPDIR/s.tdf" eve-client eve-secret

# Eve (U) cannot decrypt TOP_SECRET
test_negative "Eve (U) cannot decrypt TOP_SECRET" \
  "$TMPDIR/ts.tdf" eve-client eve-secret

# Bob (TS but no SCI) cannot decrypt TS/SCI data
test_negative "Bob (TS, no SCI) cannot decrypt TS/SCI(SI)" \
  "$TMPDIR/ts-sci.tdf" bob-client bob-secret

echo ""
echo "CROSS-DOMAIN (releasable_to tests):"

# Bob (TS, USA only) can decrypt SECRET/REL USA
test_positive "Bob (TS, rel=USA) decrypts SECRET/REL USA" \
  "$TMPDIR/s-usa.tdf" bob-client bob-secret

# Bob (TS, USA only) cannot decrypt SECRET/REL FVEY (needs GBR)
test_negative "Bob (TS, rel=USA) cannot decrypt SECRET/REL FVEY" \
  "$TMPDIR/s-fvey.tdf" bob-client bob-secret

# Carol (S, FVEY) can decrypt SECRET/REL FVEY
test_positive "Carol (S, rel=FVEY) decrypts SECRET/REL FVEY" \
  "$TMPDIR/s-fvey.tdf" carol-client carol-secret

# === Summary ===
echo ""
echo "==========================================="
echo "  RESULTS: $PASS passed, $FAIL failed ($(( PASS + FAIL )) total)"
echo "==========================================="
echo ""

for t in "${TESTS[@]}"; do
  echo "  $t"
done

echo ""
if [[ $FAIL -gt 0 ]]; then
  echo "SOME TESTS FAILED"
  exit 1
else
  echo "ALL TESTS PASSED"
  exit 0
fi
