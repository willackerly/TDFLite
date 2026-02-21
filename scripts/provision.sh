#!/usr/bin/env bash
# provision.sh — Provision TDFLite with USA classification policy
#
# Mirrors TDFBot's classification scheme:
#   - classification_level (HIERARCHY): TOP_SECRET > SECRET > CONFIDENTIAL > UNCLASSIFIED
#   - sci_control_system (ALL_OF): SI, HCS, TK
#   - releasable_to (ALL_OF): USA, GBR, CAN, AUS, NZL
#
# Subject mappings use JWT custom claims (claims mode entity resolution).
#
# Usage:
#   bash scripts/provision.sh [--host http://localhost:8080] [--idp http://localhost:15433]

set -euo pipefail

# --- Defaults ---
PLATFORM_HOST="${PLATFORM_HOST:-http://localhost:8080}"
IDP_HOST="${IDP_HOST:-http://localhost:15433}"
ADMIN_CLIENT_ID="opentdf"
ADMIN_CLIENT_SECRET="secret"
NAMESPACE_NAME="tdflite.local"

# --- Parse args ---
while [[ $# -gt 0 ]]; do
  case $1 in
    --host) PLATFORM_HOST="$2"; shift 2 ;;
    --idp)  IDP_HOST="$2"; shift 2 ;;
    *)      echo "Unknown arg: $1"; exit 1 ;;
  esac
done

echo "=== TDFLite Policy Provisioning ==="
echo "Platform: $PLATFORM_HOST"
echo "IdP:      $IDP_HOST"
echo ""

# --- Helpers ---

api_call() {
  local service="$1"
  local method="$2"
  local body="$3"
  local description="${4:-$service/$method}"

  local resp
  resp=$(curl -s -w "\n%{http_code}" -X POST \
    "${PLATFORM_HOST}/${service}/${method}" \
    -H "Authorization: Bearer ${TOKEN}" \
    -H "Content-Type: application/json" \
    -H "Connect-Protocol-Version: 1" \
    -d "$body")

  local http_code
  http_code=$(echo "$resp" | tail -1)
  local body_resp
  body_resp=$(echo "$resp" | sed '$d')

  if [[ "$http_code" != "200" ]]; then
    echo "FAIL: $description (HTTP $http_code)"
    echo "$body_resp" | jq . 2>/dev/null || echo "$body_resp"
    return 1
  fi

  echo "$body_resp"
}

get_token() {
  local client_id="$1"
  local client_secret="$2"

  local resp
  resp=$(curl -s -X POST "${IDP_HOST}/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=client_credentials&client_id=${client_id}&client_secret=${client_secret}")

  echo "$resp" | jq -r '.access_token'
}

# --- Step 0: Wait for platform health ---
echo "Waiting for platform health..."
for i in $(seq 1 30); do
  if curl -sf "${PLATFORM_HOST}/healthz" > /dev/null 2>&1; then
    echo "  Platform is healthy"
    break
  fi
  if [[ $i -eq 30 ]]; then
    echo "FAIL: Platform not healthy after 30s"
    exit 1
  fi
  sleep 1
done

# --- Step 1: Get admin token ---
echo ""
echo "--- Step 1: Get admin token ---"
TOKEN=$(get_token "$ADMIN_CLIENT_ID" "$ADMIN_CLIENT_SECRET")
if [[ -z "$TOKEN" || "$TOKEN" == "null" ]]; then
  echo "FAIL: Could not get admin token"
  exit 1
fi
echo "  Got admin token (${#TOKEN} chars)"

# --- Step 2: Create namespace ---
echo ""
echo "--- Step 2: Create namespace '$NAMESPACE_NAME' ---"
NS_RESP=$(api_call \
  "policy.namespaces.NamespaceService" \
  "CreateNamespace" \
  "{\"name\": \"$NAMESPACE_NAME\"}" \
  "Create namespace")
NS_ID=$(echo "$NS_RESP" | jq -r '.namespace.id')
echo "  Namespace ID: $NS_ID"

# --- Step 3: Create attributes ---
echo ""
echo "--- Step 3: Create attributes ---"

# 3a. classification_level — HIERARCHY (order: highest to lowest)
echo "  Creating classification_level (HIERARCHY)..."
CL_RESP=$(api_call \
  "policy.attributes.AttributesService" \
  "CreateAttribute" \
  "{
    \"namespaceId\": \"$NS_ID\",
    \"name\": \"classification_level\",
    \"rule\": \"ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY\",
    \"values\": [\"TOP_SECRET\", \"SECRET\", \"CONFIDENTIAL\", \"UNCLASSIFIED\"]
  }" \
  "Create classification_level attribute")
CL_ATTR_ID=$(echo "$CL_RESP" | jq -r '.attribute.id')
echo "    Attribute ID: $CL_ATTR_ID"

# Extract value IDs
CL_TS_ID=$(echo "$CL_RESP" | jq -r '.attribute.values[] | select(.value=="TOP_SECRET") | .id')
CL_S_ID=$(echo "$CL_RESP" | jq -r '.attribute.values[] | select(.value=="SECRET") | .id')
CL_C_ID=$(echo "$CL_RESP" | jq -r '.attribute.values[] | select(.value=="CONFIDENTIAL") | .id')
CL_U_ID=$(echo "$CL_RESP" | jq -r '.attribute.values[] | select(.value=="UNCLASSIFIED") | .id')
echo "    TOP_SECRET:   $CL_TS_ID"
echo "    SECRET:       $CL_S_ID"
echo "    CONFIDENTIAL: $CL_C_ID"
echo "    UNCLASSIFIED: $CL_U_ID"

# 3b. sci_control_system — ALL_OF
echo "  Creating sci_control_system (ALL_OF)..."
SCI_RESP=$(api_call \
  "policy.attributes.AttributesService" \
  "CreateAttribute" \
  "{
    \"namespaceId\": \"$NS_ID\",
    \"name\": \"sci_control_system\",
    \"rule\": \"ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF\",
    \"values\": [\"SI\", \"HCS\", \"TK\"]
  }" \
  "Create sci_control_system attribute")
SCI_ATTR_ID=$(echo "$SCI_RESP" | jq -r '.attribute.id')
echo "    Attribute ID: $SCI_ATTR_ID"

SCI_SI_ID=$(echo "$SCI_RESP" | jq -r '.attribute.values[] | select(.value=="SI") | .id')
SCI_HCS_ID=$(echo "$SCI_RESP" | jq -r '.attribute.values[] | select(.value=="HCS") | .id')
SCI_TK_ID=$(echo "$SCI_RESP" | jq -r '.attribute.values[] | select(.value=="TK") | .id')
echo "    SI:  $SCI_SI_ID"
echo "    HCS: $SCI_HCS_ID"
echo "    TK:  $SCI_TK_ID"

# 3c. releasable_to — ALL_OF
echo "  Creating releasable_to (ALL_OF)..."
REL_RESP=$(api_call \
  "policy.attributes.AttributesService" \
  "CreateAttribute" \
  "{
    \"namespaceId\": \"$NS_ID\",
    \"name\": \"releasable_to\",
    \"rule\": \"ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF\",
    \"values\": [\"USA\", \"GBR\", \"CAN\", \"AUS\", \"NZL\"]
  }" \
  "Create releasable_to attribute")
REL_ATTR_ID=$(echo "$REL_RESP" | jq -r '.attribute.id')
echo "    Attribute ID: $REL_ATTR_ID"

REL_USA_ID=$(echo "$REL_RESP" | jq -r '.attribute.values[] | select(.value=="USA") | .id')
REL_GBR_ID=$(echo "$REL_RESP" | jq -r '.attribute.values[] | select(.value=="GBR") | .id')
REL_CAN_ID=$(echo "$REL_RESP" | jq -r '.attribute.values[] | select(.value=="CAN") | .id')
REL_AUS_ID=$(echo "$REL_RESP" | jq -r '.attribute.values[] | select(.value=="AUS") | .id')
REL_NZL_ID=$(echo "$REL_RESP" | jq -r '.attribute.values[] | select(.value=="NZL") | .id')
echo "    USA: $REL_USA_ID"
echo "    GBR: $REL_GBR_ID"
echo "    CAN: $REL_CAN_ID"
echo "    AUS: $REL_AUS_ID"
echo "    NZL: $REL_NZL_ID"

# --- Step 4: Create subject mappings ---
#
# Subject mappings connect JWT claims → attribute entitlements.
# In claims mode, subject_external_selector_value is a dot-path into the JWT claims.
# Our identity.json users have custom_claims that become top-level JWT claims.
#
# For each classification level, we create:
#   condition: .classification_level IN ["TOP_SECRET"]
#   mapping: condition → classification_level/TOP_SECRET attr value → DECRYPT action
#
# The HIERARCHY rule then handles the "TS user can read S data" automatically.
echo ""
echo "--- Step 4: Create subject mappings ---"

create_subject_mapping() {
  local value_id="$1"
  local selector="$2"
  local operator="$3"
  local match_values="$4"  # JSON array string
  local description="$5"

  echo "  Creating mapping: $description"

  local body
  body=$(cat <<HEREDOC
{
  "attributeValueId": "$value_id",
  "actions": [
    {"standard": "STANDARD_ACTION_DECRYPT"},
    {"standard": "STANDARD_ACTION_TRANSMIT"}
  ],
  "newSubjectConditionSet": {
    "subjectSets": [
      {
        "conditionGroups": [
          {
            "booleanOperator": "CONDITION_BOOLEAN_TYPE_ENUM_AND",
            "conditions": [
              {
                "subjectExternalSelectorValue": "$selector",
                "operator": "$operator",
                "subjectExternalValues": $match_values
              }
            ]
          }
        ]
      }
    ]
  }
}
HEREDOC
)

  local resp
  resp=$(api_call \
    "policy.subjectmapping.SubjectMappingService" \
    "CreateSubjectMapping" \
    "$body" \
    "$description")

  local sm_id
  sm_id=$(echo "$resp" | jq -r '.subjectMapping.id')
  echo "    Mapping ID: $sm_id"
}

# Classification level mappings (HIERARCHY — each level maps to its own value)
create_subject_mapping "$CL_TS_ID" \
  ".classification_level" \
  "SUBJECT_MAPPING_OPERATOR_ENUM_IN" \
  '["TOP_SECRET"]' \
  "classification_level=TOP_SECRET"

create_subject_mapping "$CL_S_ID" \
  ".classification_level" \
  "SUBJECT_MAPPING_OPERATOR_ENUM_IN" \
  '["SECRET"]' \
  "classification_level=SECRET"

create_subject_mapping "$CL_C_ID" \
  ".classification_level" \
  "SUBJECT_MAPPING_OPERATOR_ENUM_IN" \
  '["CONFIDENTIAL"]' \
  "classification_level=CONFIDENTIAL"

create_subject_mapping "$CL_U_ID" \
  ".classification_level" \
  "SUBJECT_MAPPING_OPERATOR_ENUM_IN" \
  '["UNCLASSIFIED"]' \
  "classification_level=UNCLASSIFIED"

# SCI control system mappings (ALL_OF — user must have each SCI)
# We use IN_CONTAINS: the user's array claim must contain the required value
create_subject_mapping "$SCI_SI_ID" \
  ".sci_control_system" \
  "SUBJECT_MAPPING_OPERATOR_ENUM_IN_CONTAINS" \
  '["SI"]' \
  "sci_control_system=SI"

create_subject_mapping "$SCI_HCS_ID" \
  ".sci_control_system" \
  "SUBJECT_MAPPING_OPERATOR_ENUM_IN_CONTAINS" \
  '["HCS"]' \
  "sci_control_system=HCS"

create_subject_mapping "$SCI_TK_ID" \
  ".sci_control_system" \
  "SUBJECT_MAPPING_OPERATOR_ENUM_IN_CONTAINS" \
  '["TK"]' \
  "sci_control_system=TK"

# Releasable_to mappings (ALL_OF — user must have each release country)
create_subject_mapping "$REL_USA_ID" \
  ".releasable_to" \
  "SUBJECT_MAPPING_OPERATOR_ENUM_IN_CONTAINS" \
  '["USA"]' \
  "releasable_to=USA"

create_subject_mapping "$REL_GBR_ID" \
  ".releasable_to" \
  "SUBJECT_MAPPING_OPERATOR_ENUM_IN_CONTAINS" \
  '["GBR"]' \
  "releasable_to=GBR"

create_subject_mapping "$REL_CAN_ID" \
  ".releasable_to" \
  "SUBJECT_MAPPING_OPERATOR_ENUM_IN_CONTAINS" \
  '["CAN"]' \
  "releasable_to=CAN"

create_subject_mapping "$REL_AUS_ID" \
  ".releasable_to" \
  "SUBJECT_MAPPING_OPERATOR_ENUM_IN_CONTAINS" \
  '["AUS"]' \
  "releasable_to=AUS"

create_subject_mapping "$REL_NZL_ID" \
  ".releasable_to" \
  "SUBJECT_MAPPING_OPERATOR_ENUM_IN_CONTAINS" \
  '["NZL"]' \
  "releasable_to=NZL"

# --- Step 5: Verify ---
echo ""
echo "--- Step 5: Verify provisioning ---"

echo "  Listing namespaces..."
NS_LIST=$(api_call \
  "policy.namespaces.NamespaceService" \
  "ListNamespaces" \
  '{}' \
  "List namespaces")
NS_COUNT=$(echo "$NS_LIST" | jq '.namespaces | length')
echo "    Namespaces: $NS_COUNT"

echo "  Listing attributes..."
ATTR_LIST=$(api_call \
  "policy.attributes.AttributesService" \
  "ListAttributes" \
  '{}' \
  "List attributes")
ATTR_COUNT=$(echo "$ATTR_LIST" | jq '.attributes | length')
echo "    Attributes: $ATTR_COUNT"

echo "  Listing subject mappings..."
SM_LIST=$(api_call \
  "policy.subjectmapping.SubjectMappingService" \
  "ListSubjectMappings" \
  '{}' \
  "List subject mappings")
SM_COUNT=$(echo "$SM_LIST" | jq '.subjectMappings | length')
echo "    Subject mappings: $SM_COUNT"

echo ""
echo "=== Provisioning complete ==="
echo "  Namespace:        $NAMESPACE_NAME ($NS_ID)"
echo "  Attributes:       $ATTR_COUNT (classification_level, sci_control_system, releasable_to)"
echo "  Subject mappings: $SM_COUNT"
echo ""
echo "Ready for E2E testing."
