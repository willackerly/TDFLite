#!/usr/bin/env bash
# provision.sh — Provision TDFLite with USA classification policy
#
# Mirrors TDFBot's classification scheme:
#   - classification_level (HIERARCHY): TOP_SECRET > SECRET > CONFIDENTIAL > UNCLASSIFIED
#   - sci_control_system (ALL_OF): SI, HCS, TK
#   - releasable_to (ALL_OF): USA, GBR, CAN, AUS, NZL
#
# Subject mappings use JWT custom claims (claims mode entity resolution).
# Idempotent: safe to run multiple times (handles "already exists").
#
# Usage:
#   bash scripts/provision.sh [--host http://localhost:9090] [--idp http://localhost:15433]

set -uo pipefail

PLATFORM_HOST="${PLATFORM_HOST:-http://localhost:9090}"
IDP_HOST="${IDP_HOST:-http://localhost:15433}"
ADMIN_CLIENT_ID="opentdf"
ADMIN_CLIENT_SECRET="secret"
NAMESPACE_NAME="tdflite.local"
WORK="/tmp/tdflite-provision-$$"
mkdir -p "$WORK"
trap 'rm -rf "$WORK"' EXIT

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

# api_call SERVICE METHOD BODY OUTFILE
# Saves response to OUTFILE, returns 0 on 200, 1 otherwise.
api_call() {
  local service="$1" method="$2" body="$3" outfile="$4"
  local http_code
  http_code=$(curl -s -o "$outfile" -w "%{http_code}" -X POST \
    "${PLATFORM_HOST}/${service}/${method}" \
    -H "Authorization: Bearer ${TOKEN}" \
    -H "Content-Type: application/json" \
    -H "Connect-Protocol-Version: 1" \
    -d "$body")
  if [[ "$http_code" == "200" ]]; then return 0; fi
  echo "  HTTP $http_code: $(cat "$outfile")" >&2
  return 1
}

# --- Step 0: Wait for health ---
echo "Waiting for platform health..."
for i in $(seq 1 30); do
  if curl -sf "${PLATFORM_HOST}/healthz" > /dev/null 2>&1; then echo "  Healthy"; break; fi
  if [[ $i -eq 30 ]]; then echo "FAIL: not healthy after 30s"; exit 1; fi
  sleep 1
done

# --- Step 1: Get admin token ---
echo ""
echo "--- Step 1: Get admin token ---"
curl -s -X POST "${IDP_HOST}/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=${ADMIN_CLIENT_ID}&client_secret=${ADMIN_CLIENT_SECRET}" \
  | jq -r '.access_token' > "$WORK/token.txt"
TOKEN=$(cat "$WORK/token.txt")
if [[ -z "$TOKEN" || "$TOKEN" == "null" ]]; then echo "FAIL: no token"; exit 1; fi
echo "  Got token (${#TOKEN} chars)"

# --- Step 2: Create namespace ---
echo ""
echo "--- Step 2: Create namespace ---"
if api_call "policy.namespaces.NamespaceService" "CreateNamespace" \
  "{\"name\": \"$NAMESPACE_NAME\"}" "$WORK/ns.json"; then
  NS_ID=$(jq -r '.namespace.id' "$WORK/ns.json")
  echo "  Created: $NS_ID"
else
  echo "  May exist, looking up..."
  api_call "policy.namespaces.NamespaceService" "ListNamespaces" '{}' "$WORK/ns-list.json" \
    || { echo "FAIL: cannot list"; exit 1; }
  NS_ID=$(jq -r ".namespaces[] | select(.name==\"$NAMESPACE_NAME\") | .id" "$WORK/ns-list.json")
  if [[ -z "$NS_ID" ]]; then echo "FAIL: not found"; exit 1; fi
  echo "  Found: $NS_ID"
fi

# --- Step 3: Create attributes ---
echo ""
echo "--- Step 3: Create attributes ---"

# 3a. classification_level
echo "  classification_level (HIERARCHY)..."
api_call "policy.attributes.AttributesService" "CreateAttribute" \
  "{\"namespaceId\": \"$NS_ID\", \"name\": \"classification_level\", \"rule\": \"ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY\", \"values\": [\"TOP_SECRET\", \"SECRET\", \"CONFIDENTIAL\", \"UNCLASSIFIED\"]}" \
  "$WORK/cl.json" || { echo "FAIL"; exit 1; }
CL_TS_ID=$(jq -r '.attribute.values[] | select(.value=="top_secret") | .id' "$WORK/cl.json")
CL_S_ID=$(jq -r '.attribute.values[] | select(.value=="secret") | .id' "$WORK/cl.json")
CL_C_ID=$(jq -r '.attribute.values[] | select(.value=="confidential") | .id' "$WORK/cl.json")
CL_U_ID=$(jq -r '.attribute.values[] | select(.value=="unclassified") | .id' "$WORK/cl.json")
echo "    TS=$CL_TS_ID S=$CL_S_ID C=$CL_C_ID U=$CL_U_ID"

# 3b. sci_control_system
echo "  sci_control_system (ALL_OF)..."
api_call "policy.attributes.AttributesService" "CreateAttribute" \
  "{\"namespaceId\": \"$NS_ID\", \"name\": \"sci_control_system\", \"rule\": \"ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF\", \"values\": [\"SI\", \"HCS\", \"TK\"]}" \
  "$WORK/sci.json" || { echo "FAIL"; exit 1; }
SCI_SI_ID=$(jq -r '.attribute.values[] | select(.value=="si") | .id' "$WORK/sci.json")
SCI_HCS_ID=$(jq -r '.attribute.values[] | select(.value=="hcs") | .id' "$WORK/sci.json")
SCI_TK_ID=$(jq -r '.attribute.values[] | select(.value=="tk") | .id' "$WORK/sci.json")
echo "    SI=$SCI_SI_ID HCS=$SCI_HCS_ID TK=$SCI_TK_ID"

# 3c. releasable_to
echo "  releasable_to (ALL_OF)..."
api_call "policy.attributes.AttributesService" "CreateAttribute" \
  "{\"namespaceId\": \"$NS_ID\", \"name\": \"releasable_to\", \"rule\": \"ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF\", \"values\": [\"USA\", \"GBR\", \"CAN\", \"AUS\", \"NZL\"]}" \
  "$WORK/rel.json" || { echo "FAIL"; exit 1; }
REL_USA_ID=$(jq -r '.attribute.values[] | select(.value=="usa") | .id' "$WORK/rel.json")
REL_GBR_ID=$(jq -r '.attribute.values[] | select(.value=="gbr") | .id' "$WORK/rel.json")
REL_CAN_ID=$(jq -r '.attribute.values[] | select(.value=="can") | .id' "$WORK/rel.json")
REL_AUS_ID=$(jq -r '.attribute.values[] | select(.value=="aus") | .id' "$WORK/rel.json")
REL_NZL_ID=$(jq -r '.attribute.values[] | select(.value=="nzl") | .id' "$WORK/rel.json")
echo "    USA=$REL_USA_ID GBR=$REL_GBR_ID CAN=$REL_CAN_ID AUS=$REL_AUS_ID NZL=$REL_NZL_ID"

# --- Step 4: Create subject mappings ---
echo ""
echo "--- Step 4: Create subject mappings ---"

create_sm() {
  local vid="$1" sel="$2" op="$3" vals="$4" desc="$5"
  local body="{\"attributeValueId\":\"$vid\",\"actions\":[{\"name\":\"read\"},{\"name\":\"create\"}],\"newSubjectConditionSet\":{\"subjectSets\":[{\"conditionGroups\":[{\"booleanOperator\":\"CONDITION_BOOLEAN_TYPE_ENUM_AND\",\"conditions\":[{\"subjectExternalSelectorValue\":\"$sel\",\"operator\":\"$op\",\"subjectExternalValues\":$vals}]}]}]}}"
  if api_call "policy.subjectmapping.SubjectMappingService" "CreateSubjectMapping" "$body" "$WORK/sm.json"; then
    echo "  $desc -> $(jq -r '.subjectMapping.id' "$WORK/sm.json")"
  else
    echo "  $desc -> FAILED" >&2
  fi
}

create_sm "$CL_TS_ID" ".classification_level" "SUBJECT_MAPPING_OPERATOR_ENUM_IN" '["TOP_SECRET"]' "cl=TS"
create_sm "$CL_S_ID" ".classification_level" "SUBJECT_MAPPING_OPERATOR_ENUM_IN" '["SECRET"]' "cl=S"
create_sm "$CL_C_ID" ".classification_level" "SUBJECT_MAPPING_OPERATOR_ENUM_IN" '["CONFIDENTIAL"]' "cl=C"
create_sm "$CL_U_ID" ".classification_level" "SUBJECT_MAPPING_OPERATOR_ENUM_IN" '["UNCLASSIFIED"]' "cl=U"

create_sm "$SCI_SI_ID" ".sci_control_system[]" "SUBJECT_MAPPING_OPERATOR_ENUM_IN" '["SI"]' "sci=SI"
create_sm "$SCI_HCS_ID" ".sci_control_system[]" "SUBJECT_MAPPING_OPERATOR_ENUM_IN" '["HCS"]' "sci=HCS"
create_sm "$SCI_TK_ID" ".sci_control_system[]" "SUBJECT_MAPPING_OPERATOR_ENUM_IN" '["TK"]' "sci=TK"

create_sm "$REL_USA_ID" ".releasable_to[]" "SUBJECT_MAPPING_OPERATOR_ENUM_IN" '["USA"]' "rel=USA"
create_sm "$REL_GBR_ID" ".releasable_to[]" "SUBJECT_MAPPING_OPERATOR_ENUM_IN" '["GBR"]' "rel=GBR"
create_sm "$REL_CAN_ID" ".releasable_to[]" "SUBJECT_MAPPING_OPERATOR_ENUM_IN" '["CAN"]' "rel=CAN"
create_sm "$REL_AUS_ID" ".releasable_to[]" "SUBJECT_MAPPING_OPERATOR_ENUM_IN" '["AUS"]' "rel=AUS"
create_sm "$REL_NZL_ID" ".releasable_to[]" "SUBJECT_MAPPING_OPERATOR_ENUM_IN" '["NZL"]' "rel=NZL"

# --- Step 5: Verify ---
echo ""
echo "--- Step 5: Verify ---"
api_call "policy.namespaces.NamespaceService" "ListNamespaces" '{}' "$WORK/v1.json" && echo "  Namespaces: $(jq '.namespaces | length' "$WORK/v1.json")"
api_call "policy.attributes.AttributesService" "ListAttributes" '{}' "$WORK/v2.json" && echo "  Attributes: $(jq '.attributes | length' "$WORK/v2.json")"
api_call "policy.subjectmapping.SubjectMappingService" "ListSubjectMappings" '{}' "$WORK/v3.json" && echo "  Subject mappings: $(jq '.subjectMappings | length' "$WORK/v3.json")"

echo ""
echo "=== Provisioning complete ==="
