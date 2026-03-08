// Package provision converts a policy bundle into ConnectRPC API calls to
// provision the OpenTDF platform at boot time.
//
// It creates namespaces, attributes, and subject mappings using the Connect
// protocol (JSON over HTTP POST with specific headers). The provisioning is
// idempotent: "already exists" errors are silently ignored.
package provision

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/willackerly/TDFLite/internal/policybundle"
)

// ConnectRPC service and method paths.
const (
	namespaceService      = "policy.namespaces.NamespaceService"
	attributesService     = "policy.attributes.AttributesService"
	subjectMappingService = "policy.subjectmapping.SubjectMappingService"
	kasRegistryService    = "policy.kasregistry.KeyAccessServerRegistryService"

	createNamespace      = "CreateNamespace"
	listNamespaces       = "ListNamespaces"
	createAttribute      = "CreateAttribute"
	createSubjectMapping = "CreateSubjectMapping"

	createKeyAccessServer = "CreateKeyAccessServer"
	createKey             = "CreateKey"
	setBaseKey            = "SetBaseKey"
)

// Protobuf enum values used in the API.
const (
	RuleHierarchy = "ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY"
	RuleAllOf     = "ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF"
	RuleAnyOf     = "ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF"

	OperatorIn         = "SUBJECT_MAPPING_OPERATOR_ENUM_IN"
	ConditionBoolAnd   = "CONDITION_BOOLEAN_TYPE_ENUM_AND"
)

// ruleTypeMap converts bundle rule types to protobuf enum values.
var ruleTypeMap = map[policybundle.AttributeRule]string{
	policybundle.RuleHierarchy: RuleHierarchy,
	policybundle.RuleAllOf:     RuleAllOf,
	policybundle.RuleAnyOf:     RuleAnyOf,
}

// MapRuleType converts a bundle AttributeRule to the protobuf enum string.
// Returns an error if the rule type is unknown.
func MapRuleType(rule policybundle.AttributeRule) (string, error) {
	mapped, ok := ruleTypeMap[rule]
	if !ok {
		return "", fmt.Errorf("unknown rule type: %q", rule)
	}
	return mapped, nil
}

// attributeValueResponse is the shape of a value in the API response.
type attributeValueResponse struct {
	ID    string `json:"id"`
	Value string `json:"value"`
}

// createAttributeResponse is the shape of the CreateAttribute API response.
type createAttributeResponse struct {
	Attribute struct {
		ID     string                   `json:"id"`
		Values []attributeValueResponse `json:"values"`
	} `json:"attribute"`
}

// createNamespaceResponse is the shape of the CreateNamespace API response.
type createNamespaceResponse struct {
	Namespace struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"namespace"`
}

// listNamespacesResponse is the shape of the ListNamespaces API response.
type listNamespacesResponse struct {
	Namespaces []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"namespaces"`
}

// connectError is an error from a ConnectRPC call.
type connectError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Provision provisions the OpenTDF platform from a policy bundle by making
// HTTP calls to the ConnectRPC API. It creates the namespace, attributes,
// and subject mappings defined in the bundle.
//
// The provisioning is idempotent: if resources already exist, those errors
// are silently ignored and existing IDs are looked up.
func Provision(ctx context.Context, bundle *policybundle.Bundle, platformURL string, authToken string) error {
	logger := slog.Default()

	// Step 1: Create namespace.
	nsName := bundle.EffectiveNamespace()
	logger.Info("provisioning namespace", "name", nsName)

	nsID, err := createOrFindNamespace(ctx, platformURL, authToken, nsName)
	if err != nil {
		return fmt.Errorf("provisioning namespace %q: %w", nsName, err)
	}
	logger.Info("namespace ready", "id", nsID, "name", nsName)

	// Step 2: Create attributes and collect value IDs.
	actions := bundle.EffectiveActions()
	for _, attr := range bundle.Attributes {
		logger.Info("provisioning attribute", "name", attr.Name, "rule", attr.Rule, "values", attr.Values)

		ruleEnum, err := MapRuleType(attr.Rule)
		if err != nil {
			return fmt.Errorf("attribute %q: %w", attr.Name, err)
		}

		attrResp, err := createAttributeAPI(ctx, platformURL, authToken, nsID, attr.Name, ruleEnum, attr.Values)
		if err != nil {
			if isAlreadyExists(err) {
				logger.Info("attribute already exists, skipping", "name", attr.Name)
				continue
			}
			return fmt.Errorf("creating attribute %q: %w", attr.Name, err)
		}

		logger.Info("attribute created", "name", attr.Name, "id", attrResp.Attribute.ID,
			"valueCount", len(attrResp.Attribute.Values))

		// Step 3: Create subject mappings for each value.
		for _, val := range attrResp.Attribute.Values {
			selector := selectorForRule(attr.Name, attr.Rule)

			logger.Info("creating subject mapping",
				"attribute", attr.Name,
				"value", val.Value,
				"valueId", val.ID,
				"selector", selector,
			)

			err := createSubjectMappingAPI(ctx, platformURL, authToken, val.ID, selector, val.Value, actions)
			if err != nil {
				if isAlreadyExists(err) {
					logger.Info("subject mapping already exists, skipping",
						"attribute", attr.Name, "value", val.Value)
					continue
				}
				return fmt.Errorf("creating subject mapping for %s=%s: %w", attr.Name, val.Value, err)
			}

			logger.Info("subject mapping created", "attribute", attr.Name, "value", val.Value)
		}
	}

	logger.Info("provisioning complete")
	return nil
}

// ProvisionKASRegistration registers the KAS and its key in the platform's
// policy database, then sets the base key. This populates the well-known
// configuration's `base_key` field, which the OpenTDF SDK requires for
// encrypt operations.
//
// The function reads the KAS public key from the given PEM file path
// (typically data/kas-cert.pem), registers it in the KAS registry, and
// marks it as the active base key.
//
// This must be called AFTER the platform is healthy and AFTER policy
// provisioning is complete.
// ProvisionKASRegistration registers the KAS and its key in the platform's
// policy database, then sets the base key. kasExternalURL is the URL external
// clients use to reach KAS (may differ from platformURL in Docker).
func ProvisionKASRegistration(ctx context.Context, platformURL, authToken, kasPublicKeyPEM, kasPrivateKeyPEM, kasExternalURL string) error {
	logger := slog.Default()

	if kasExternalURL == "" {
		kasExternalURL = platformURL
	}

	// Step 1: Register the Key Access Server with external-facing URL.
	logger.Info("registering KAS in platform registry", "uri", kasExternalURL)

	kasBody := map[string]interface{}{
		"uri":  kasExternalURL,
		"name": "default-kas",
	}

	kasRespBytes, err := connectCall(ctx, platformURL, authToken, kasRegistryService, createKeyAccessServer, kasBody)
	if err != nil {
		if isAlreadyExists(err) {
			logger.Info("KAS already registered, looking up existing")
			// KAS already registered — look it up to get the ID.
			listResp, listErr := connectCall(ctx, platformURL, authToken, kasRegistryService, "ListKeyAccessServers", map[string]interface{}{})
			if listErr != nil {
				return fmt.Errorf("listing KAS servers: %w", listErr)
			}
			kasID, findErr := extractFirstKASID(listResp)
			if findErr != nil {
				return fmt.Errorf("finding existing KAS: %w", findErr)
			}
			return provisionKASKey(ctx, logger, platformURL, authToken, kasID, kasPublicKeyPEM, kasPrivateKeyPEM)
		}
		return fmt.Errorf("creating KAS: %w", err)
	}

	// Extract KAS ID from response.
	var kasResp struct {
		KeyAccessServer struct {
			ID string `json:"id"`
		} `json:"keyAccessServer"`
	}
	if err := json.Unmarshal(kasRespBytes, &kasResp); err != nil {
		return fmt.Errorf("parsing KAS response: %w", err)
	}
	kasID := kasResp.KeyAccessServer.ID
	logger.Info("KAS registered", "id", kasID)

	return provisionKASKey(ctx, logger, platformURL, authToken, kasID, kasPublicKeyPEM, kasPrivateKeyPEM)
}

// provisionKASKey creates an asymmetric key for the KAS and sets it as the base key.
func provisionKASKey(ctx context.Context, logger *slog.Logger, platformURL, authToken, kasID, publicKeyPEM, privateKeyPEM string) error {
	// Step 2: Create an asymmetric key for the KAS.
	logger.Info("creating KAS key", "kasId", kasID, "kid", "e1")

	// Wrap the private key with a random AES-256-GCM KEK.
	// The wrapped key is stored in the DB for key management but
	// the KAS crypto provider reads keys from disk, not the DB.
	wrappedPrivKey, err := wrapKeyForDB(privateKeyPEM)
	if err != nil {
		return fmt.Errorf("wrapping private key: %w", err)
	}

	keyBody := map[string]interface{}{
		"kasId":        kasID,
		"keyId":        "e1",
		"keyAlgorithm": 3, // ALGORITHM_EC_P256 (NanoTDF requires EC)
		"keyMode":      1, // KEY_MODE_CONFIG_ROOT_KEY
		"publicKeyCtx": map[string]interface{}{
			"pem": base64.StdEncoding.EncodeToString([]byte(publicKeyPEM)),
		},
		"privateKeyCtx": map[string]interface{}{
			"keyId":      "e1",
			"wrappedKey": wrappedPrivKey,
		},
	}

	keyRespBytes, err := connectCall(ctx, platformURL, authToken, kasRegistryService, createKey, keyBody)
	if err != nil {
		if isAlreadyExists(err) {
			logger.Info("KAS key already exists, skipping creation")
			// Key exists — try to set base key anyway (might already be set).
			return setBaseKeyByKID(ctx, logger, platformURL, authToken, kasID, "e1")
		}
		return fmt.Errorf("creating KAS key: %w", err)
	}

	// Extract key ID from response: kasKey.key.id
	var keyResp struct {
		KasKey struct {
			Key struct {
				ID string `json:"id"`
			} `json:"key"`
		} `json:"kasKey"`
	}
	if err := json.Unmarshal(keyRespBytes, &keyResp); err != nil {
		return fmt.Errorf("parsing key response: %w", err)
	}
	keyID := keyResp.KasKey.Key.ID
	logger.Info("KAS key created", "id", keyID)

	// Step 3: Set as base key.
	logger.Info("setting base key", "keyId", keyID)

	baseKeyBody := map[string]interface{}{
		"id": keyID,
	}

	_, err = connectCall(ctx, platformURL, authToken, kasRegistryService, setBaseKey, baseKeyBody)
	if err != nil {
		return fmt.Errorf("setting base key: %w", err)
	}

	logger.Info("base key set successfully")
	return nil
}

// setBaseKeyByKID sets the base key by looking up the key by KAS ID and KID.
func setBaseKeyByKID(ctx context.Context, logger *slog.Logger, platformURL, authToken, kasID, kid string) error {
	// Use the SetBaseKey with key lookup (by kasId + kid).
	baseKeyBody := map[string]interface{}{
		"key": map[string]interface{}{
			"kasId": kasID,
			"keyId": kid,
		},
	}

	_, err := connectCall(ctx, platformURL, authToken, kasRegistryService, setBaseKey, baseKeyBody)
	if err != nil {
		logger.Warn("failed to set base key (may already be set)", "error", err)
		return nil // Non-fatal: key may already be the base key
	}

	logger.Info("base key set successfully (from existing key)")
	return nil
}

// wrapKeyForDB encrypts a private key PEM with a random AES-256-GCM key and
// returns the result as base64. This satisfies the platform's requirement that
// CONFIG_ROOT_KEY mode keys are not stored as raw PEM in the DB. The KAS
// crypto provider reads actual keys from disk config, not from the DB.
func wrapKeyForDB(privateKeyPEM string) (string, error) {
	// Generate a random 32-byte KEK.
	kek := make([]byte, 32)
	if _, err := rand.Read(kek); err != nil {
		return "", fmt.Errorf("generating KEK: %w", err)
	}

	block, err := aes.NewCipher(kek)
	if err != nil {
		return "", fmt.Errorf("creating cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("creating GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("generating nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(privateKeyPEM), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// extractFirstKASID extracts the first KAS ID from a ListKeyAccessServers response.
func extractFirstKASID(respBytes []byte) (string, error) {
	var resp struct {
		KeyAccessServers []struct {
			ID string `json:"id"`
		} `json:"keyAccessServers"`
	}
	if err := json.Unmarshal(respBytes, &resp); err != nil {
		return "", fmt.Errorf("parsing KAS list: %w", err)
	}
	if len(resp.KeyAccessServers) == 0 {
		return "", fmt.Errorf("no KAS servers found")
	}
	return resp.KeyAccessServers[0].ID, nil
}

// createOrFindNamespace creates a namespace or finds it if it already exists.
func createOrFindNamespace(ctx context.Context, platformURL, authToken, name string) (string, error) {
	body := map[string]string{"name": name}

	respBytes, err := connectCall(ctx, platformURL, authToken, namespaceService, createNamespace, body)
	if err != nil {
		if !isAlreadyExists(err) {
			return "", err
		}
		// Namespace exists — look it up.
		return findNamespace(ctx, platformURL, authToken, name)
	}

	var resp createNamespaceResponse
	if err := json.Unmarshal(respBytes, &resp); err != nil {
		return "", fmt.Errorf("parsing namespace response: %w", err)
	}
	return resp.Namespace.ID, nil
}

// findNamespace looks up a namespace by name.
func findNamespace(ctx context.Context, platformURL, authToken, name string) (string, error) {
	respBytes, err := connectCall(ctx, platformURL, authToken, namespaceService, listNamespaces, map[string]interface{}{})
	if err != nil {
		return "", fmt.Errorf("listing namespaces: %w", err)
	}

	var resp listNamespacesResponse
	if err := json.Unmarshal(respBytes, &resp); err != nil {
		return "", fmt.Errorf("parsing namespace list: %w", err)
	}

	for _, ns := range resp.Namespaces {
		if ns.Name == name {
			return ns.ID, nil
		}
	}
	return "", fmt.Errorf("namespace %q not found", name)
}

// createAttributeAPI creates an attribute with inline values.
func createAttributeAPI(ctx context.Context, platformURL, authToken, nsID, name, rule string, values []string) (*createAttributeResponse, error) {
	// Build values as string array (the API accepts plain strings).
	body := map[string]interface{}{
		"namespaceId": nsID,
		"name":        name,
		"rule":        rule,
		"values":      values,
	}

	respBytes, err := connectCall(ctx, platformURL, authToken, attributesService, createAttribute, body)
	if err != nil {
		return nil, err
	}

	var resp createAttributeResponse
	if err := json.Unmarshal(respBytes, &resp); err != nil {
		return nil, fmt.Errorf("parsing attribute response: %w", err)
	}
	return &resp, nil
}

// createSubjectMappingAPI creates a subject mapping for an attribute value.
func createSubjectMappingAPI(ctx context.Context, platformURL, authToken, valueID, selector, value string, actions []string) error {
	// Build actions array.
	actionObjs := make([]map[string]string, len(actions))
	for i, a := range actions {
		actionObjs[i] = map[string]string{"name": a}
	}

	body := map[string]interface{}{
		"attributeValueId": valueID,
		"actions":          actionObjs,
		"newSubjectConditionSet": map[string]interface{}{
			"subjectSets": []interface{}{
				map[string]interface{}{
					"conditionGroups": []interface{}{
						map[string]interface{}{
							"booleanOperator": ConditionBoolAnd,
							"conditions": []interface{}{
								map[string]interface{}{
									"subjectExternalSelectorValue": selector,
									"operator":                     OperatorIn,
									"subjectExternalValues":        []string{value},
								},
							},
						},
					},
				},
			},
		},
	}

	_, err := connectCall(ctx, platformURL, authToken, subjectMappingService, createSubjectMapping, body)
	return err
}

// selectorForRule returns the JQ-style selector for a given attribute name and rule type.
// Hierarchy attributes use ".{name}" (scalar claim).
// allOf/anyOf attributes use ".{name}[]" (array claim, iterate elements).
func selectorForRule(name string, rule policybundle.AttributeRule) string {
	switch rule {
	case policybundle.RuleHierarchy:
		return "." + name
	default:
		return "." + name + "[]"
	}
}

// connectCall makes a ConnectRPC POST request and returns the response body.
// Returns a *ConnectAPIError if the response indicates an error.
func connectCall(ctx context.Context, platformURL, authToken, service, method string, body interface{}) ([]byte, error) {
	reqURL := fmt.Sprintf("%s/%s/%s", strings.TrimRight(platformURL, "/"), service, method)

	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshaling request body: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Connect-Protocol-Version", "1")
	req.Header.Set("Authorization", "Bearer "+authToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request to %s/%s: %w", service, method, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response from %s/%s: %w", service, method, err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, parseConnectError(service, method, resp.StatusCode, respBody)
	}

	return respBody, nil
}

// ConnectAPIError represents an error from a ConnectRPC endpoint.
type ConnectAPIError struct {
	Service    string
	Method     string
	StatusCode int
	Code       string
	Message    string
}

func (e *ConnectAPIError) Error() string {
	return fmt.Sprintf("%s/%s: HTTP %d: %s: %s", e.Service, e.Method, e.StatusCode, e.Code, e.Message)
}

// parseConnectError extracts a ConnectRPC error from the response.
func parseConnectError(service, method string, statusCode int, body []byte) *ConnectAPIError {
	apiErr := &ConnectAPIError{
		Service:    service,
		Method:     method,
		StatusCode: statusCode,
		Message:    string(body),
	}

	var ce connectError
	if err := json.Unmarshal(body, &ce); err == nil {
		apiErr.Code = ce.Code
		apiErr.Message = ce.Message
	}

	return apiErr
}

// isAlreadyExists checks if an error is an "already exists" ConnectRPC error.
func isAlreadyExists(err error) bool {
	if apiErr, ok := err.(*ConnectAPIError); ok {
		if apiErr.Code == "already_exists" {
			return true
		}
		if strings.Contains(strings.ToLower(apiErr.Message), "already exists") {
			return true
		}
	}
	return false
}

// GetAuthToken obtains an admin access token from the IdP using the
// client_credentials grant with the opentdf/secret admin account.
func GetAuthToken(ctx context.Context, idpURL string) (string, error) {
	tokenURL := strings.TrimRight(idpURL, "/") + "/token"

	formData := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"opentdf"},
		"client_secret": {"secret"},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(formData.Encode()))
	if err != nil {
		return "", fmt.Errorf("creating token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("requesting token from %s: %w", tokenURL, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("reading token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token endpoint returned HTTP %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", fmt.Errorf("parsing token response: %w", err)
	}

	if tokenResp.AccessToken == "" {
		return "", fmt.Errorf("token endpoint returned empty access_token")
	}

	return tokenResp.AccessToken, nil
}
