package provision

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/willackerly/TDFLite/internal/policybundle"
)

// requestCapture stores captured requests for verification.
type requestCapture struct {
	mu       sync.Mutex
	requests []capturedRequest
}

type capturedRequest struct {
	Path    string
	Body    map[string]interface{}
	Headers http.Header
}

func (rc *requestCapture) add(path string, body map[string]interface{}, headers http.Header) {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	rc.requests = append(rc.requests, capturedRequest{
		Path:    path,
		Body:    body,
		Headers: headers.Clone(),
	})
}

func (rc *requestCapture) all() []capturedRequest {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	cp := make([]capturedRequest, len(rc.requests))
	copy(cp, rc.requests)
	return cp
}

// newMockServer creates an httptest server that captures requests and returns
// canned responses based on the path.
func newMockServer(t *testing.T, capture *requestCapture, responses map[string]string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make(map[string]interface{})
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("failed to decode request body: %v", err)
		}
		capture.add(r.URL.Path, body, r.Header)

		resp, ok := responses[r.URL.Path]
		if !ok {
			t.Errorf("unexpected request to %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(resp))
	}))
}

// newErrorMockServer creates a server that returns Connect error responses.
func newErrorMockServer(t *testing.T, capture *requestCapture, errorCode string, errorMessage string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make(map[string]interface{})
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("failed to decode request body: %v", err)
		}
		capture.add(r.URL.Path, body, r.Header)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		resp := map[string]string{"code": errorCode, "message": errorMessage}
		respBytes, _ := json.Marshal(resp)
		_, _ = w.Write(respBytes)
	}))
}

func TestProvisionNamespace(t *testing.T) {
	capture := &requestCapture{}
	responses := map[string]string{
		"/policy.namespaces.NamespaceService/CreateNamespace": `{"namespace":{"id":"ns-123","name":"tdflite.local"}}`,
	}
	srv := newMockServer(t, capture, responses)
	defer srv.Close()

	bundle := &policybundle.Bundle{
		Namespace:  "tdflite.local",
		Attributes: []policybundle.Attribute{},
		Identities: map[string]policybundle.Identity{"admin": {Admin: true}},
	}

	err := Provision(context.Background(), bundle, srv.URL, "test-token")
	if err != nil {
		t.Fatalf("Provision failed: %v", err)
	}

	reqs := capture.all()
	if len(reqs) != 1 {
		t.Fatalf("expected 1 request, got %d", len(reqs))
	}

	req := reqs[0]

	// Verify path.
	if req.Path != "/policy.namespaces.NamespaceService/CreateNamespace" {
		t.Errorf("unexpected path: %s", req.Path)
	}

	// Verify body.
	if name, _ := req.Body["name"].(string); name != "tdflite.local" {
		t.Errorf("expected namespace name 'tdflite.local', got %q", name)
	}

	// Verify headers.
	if ct := req.Headers.Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected Content-Type 'application/json', got %q", ct)
	}
	if cpv := req.Headers.Get("Connect-Protocol-Version"); cpv != "1" {
		t.Errorf("expected Connect-Protocol-Version '1', got %q", cpv)
	}
	if auth := req.Headers.Get("Authorization"); auth != "Bearer test-token" {
		t.Errorf("expected Authorization 'Bearer test-token', got %q", auth)
	}
}

func TestProvisionAttributes(t *testing.T) {
	capture := &requestCapture{}
	responses := map[string]string{
		"/policy.namespaces.NamespaceService/CreateNamespace": `{"namespace":{"id":"ns-123","name":"tdflite.local"}}`,
		"/policy.attributes.AttributesService/CreateAttribute": `{"attribute":{"id":"attr-1","values":[{"id":"val-1","value":"top_secret"},{"id":"val-2","value":"secret"}]}}`,
		"/policy.subjectmapping.SubjectMappingService/CreateSubjectMapping": `{"subjectMapping":{"id":"sm-1"}}`,
	}
	srv := newMockServer(t, capture, responses)
	defer srv.Close()

	bundle := &policybundle.Bundle{
		Namespace: "tdflite.local",
		Attributes: []policybundle.Attribute{
			{
				Name:   "classification_level",
				Rule:   policybundle.RuleHierarchy,
				Values: []string{"TOP_SECRET", "SECRET"},
			},
		},
		Identities: map[string]policybundle.Identity{"admin": {Admin: true}},
	}

	err := Provision(context.Background(), bundle, srv.URL, "test-token")
	if err != nil {
		t.Fatalf("Provision failed: %v", err)
	}

	reqs := capture.all()
	// 1 namespace + 1 attribute + 2 subject mappings = 4 requests
	if len(reqs) != 4 {
		t.Fatalf("expected 4 requests, got %d", len(reqs))
	}

	// Second request should be CreateAttribute.
	attrReq := reqs[1]
	if attrReq.Path != "/policy.attributes.AttributesService/CreateAttribute" {
		t.Errorf("expected CreateAttribute path, got %s", attrReq.Path)
	}

	// Verify namespaceId.
	if nsID, _ := attrReq.Body["namespaceId"].(string); nsID != "ns-123" {
		t.Errorf("expected namespaceId 'ns-123', got %q", nsID)
	}

	// Verify attribute name.
	if name, _ := attrReq.Body["name"].(string); name != "classification_level" {
		t.Errorf("expected attribute name 'classification_level', got %q", name)
	}

	// Verify rule type mapping.
	if rule, _ := attrReq.Body["rule"].(string); rule != RuleHierarchy {
		t.Errorf("expected rule %q, got %q", RuleHierarchy, rule)
	}

	// Verify values are string array.
	vals, ok := attrReq.Body["values"].([]interface{})
	if !ok {
		t.Fatalf("expected values to be array, got %T", attrReq.Body["values"])
	}
	if len(vals) != 2 {
		t.Fatalf("expected 2 values, got %d", len(vals))
	}
	if v, _ := vals[0].(string); v != "TOP_SECRET" {
		t.Errorf("expected first value 'TOP_SECRET', got %q", v)
	}
	if v, _ := vals[1].(string); v != "SECRET" {
		t.Errorf("expected second value 'SECRET', got %q", v)
	}
}

func TestProvisionSubjectMappings(t *testing.T) {
	capture := &requestCapture{}
	responses := map[string]string{
		"/policy.namespaces.NamespaceService/CreateNamespace":               `{"namespace":{"id":"ns-123","name":"tdflite.local"}}`,
		"/policy.attributes.AttributesService/CreateAttribute":              `{"attribute":{"id":"attr-1","values":[{"id":"val-si","value":"si"},{"id":"val-hcs","value":"hcs"}]}}`,
		"/policy.subjectmapping.SubjectMappingService/CreateSubjectMapping": `{"subjectMapping":{"id":"sm-1"}}`,
	}
	srv := newMockServer(t, capture, responses)
	defer srv.Close()

	bundle := &policybundle.Bundle{
		Namespace: "tdflite.local",
		Attributes: []policybundle.Attribute{
			{
				Name:   "sci_control",
				Rule:   policybundle.RuleAllOf,
				Values: []string{"SI", "HCS"},
			},
		},
		Identities: map[string]policybundle.Identity{"admin": {Admin: true}},
	}

	err := Provision(context.Background(), bundle, srv.URL, "test-token")
	if err != nil {
		t.Fatalf("Provision failed: %v", err)
	}

	reqs := capture.all()
	// 1 namespace + 1 attribute + 2 subject mappings = 4 requests
	if len(reqs) != 4 {
		t.Fatalf("expected 4 requests, got %d", len(reqs))
	}

	// Check first subject mapping (SI).
	smReq1 := reqs[2]
	if smReq1.Path != "/policy.subjectmapping.SubjectMappingService/CreateSubjectMapping" {
		t.Errorf("expected CreateSubjectMapping path, got %s", smReq1.Path)
	}

	// Verify attributeValueId.
	if vid, _ := smReq1.Body["attributeValueId"].(string); vid != "val-si" {
		t.Errorf("expected attributeValueId 'val-si', got %q", vid)
	}

	// Verify selector uses [] for allOf rule.
	condSet := extractConditionSet(t, smReq1.Body)
	if condSet.selector != ".sci_control[]" {
		t.Errorf("expected selector '.sci_control[]', got %q", condSet.selector)
	}
	if condSet.operator != OperatorIn {
		t.Errorf("expected operator %q, got %q", OperatorIn, condSet.operator)
	}
	if len(condSet.values) != 1 || condSet.values[0] != "si" {
		t.Errorf("expected values [\"si\"], got %v", condSet.values)
	}

	// Check second subject mapping (HCS).
	smReq2 := reqs[3]
	condSet2 := extractConditionSet(t, smReq2.Body)
	if condSet2.selector != ".sci_control[]" {
		t.Errorf("expected selector '.sci_control[]', got %q", condSet2.selector)
	}
	if len(condSet2.values) != 1 || condSet2.values[0] != "hcs" {
		t.Errorf("expected values [\"hcs\"], got %v", condSet2.values)
	}
}

func TestProvisionFull(t *testing.T) {
	capture := &requestCapture{}
	attrCallCount := 0
	var attrMu sync.Mutex

	// Custom server that returns different attribute responses per call.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make(map[string]interface{})
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("failed to decode body: %v", err)
		}
		capture.add(r.URL.Path, body, r.Header)

		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/policy.namespaces.NamespaceService/CreateNamespace":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"namespace":{"id":"ns-1","name":"tdflite.local"}}`))

		case "/policy.attributes.AttributesService/CreateAttribute":
			attrMu.Lock()
			idx := attrCallCount
			attrCallCount++
			attrMu.Unlock()

			w.WriteHeader(http.StatusOK)
			switch idx {
			case 0:
				_, _ = w.Write([]byte(`{"attribute":{"id":"attr-cl","values":[{"id":"v-ts","value":"top_secret"},{"id":"v-s","value":"secret"}]}}`))
			case 1:
				_, _ = w.Write([]byte(`{"attribute":{"id":"attr-sci","values":[{"id":"v-si","value":"si"}]}}`))
			case 2:
				_, _ = w.Write([]byte(`{"attribute":{"id":"attr-rel","values":[{"id":"v-usa","value":"usa"}]}}`))
			}

		case "/policy.subjectmapping.SubjectMappingService/CreateSubjectMapping":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"subjectMapping":{"id":"sm-auto"}}`))

		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	bundle := &policybundle.Bundle{
		Namespace: "tdflite.local",
		Attributes: []policybundle.Attribute{
			{Name: "classification_level", Rule: policybundle.RuleHierarchy, Values: []string{"TOP_SECRET", "SECRET"}},
			{Name: "sci_control", Rule: policybundle.RuleAllOf, Values: []string{"SI"}},
			{Name: "releasable_to", Rule: policybundle.RuleAnyOf, Values: []string{"USA"}},
		},
		Identities: map[string]policybundle.Identity{"admin": {Admin: true}},
	}

	err := Provision(context.Background(), bundle, srv.URL, "test-token")
	if err != nil {
		t.Fatalf("Provision failed: %v", err)
	}

	reqs := capture.all()
	// 1 namespace + 3 attributes + 4 subject mappings (2+1+1) = 8
	if len(reqs) != 8 {
		t.Fatalf("expected 8 requests, got %d", len(reqs))
	}

	// Verify call sequence.
	expectedPaths := []string{
		"/policy.namespaces.NamespaceService/CreateNamespace",
		"/policy.attributes.AttributesService/CreateAttribute",
		"/policy.subjectmapping.SubjectMappingService/CreateSubjectMapping",
		"/policy.subjectmapping.SubjectMappingService/CreateSubjectMapping",
		"/policy.attributes.AttributesService/CreateAttribute",
		"/policy.subjectmapping.SubjectMappingService/CreateSubjectMapping",
		"/policy.attributes.AttributesService/CreateAttribute",
		"/policy.subjectmapping.SubjectMappingService/CreateSubjectMapping",
	}
	for i, expected := range expectedPaths {
		if reqs[i].Path != expected {
			t.Errorf("request[%d]: expected %s, got %s", i, expected, reqs[i].Path)
		}
	}

	// Count by type.
	nsCalls, attrCalls, smCalls := 0, 0, 0
	for _, req := range reqs {
		switch {
		case strings.Contains(req.Path, "NamespaceService"):
			nsCalls++
		case strings.Contains(req.Path, "AttributesService"):
			attrCalls++
		case strings.Contains(req.Path, "SubjectMappingService"):
			smCalls++
		}
	}
	if nsCalls != 1 {
		t.Errorf("expected 1 namespace call, got %d", nsCalls)
	}
	if attrCalls != 3 {
		t.Errorf("expected 3 attribute calls, got %d", attrCalls)
	}
	if smCalls != 4 {
		t.Errorf("expected 4 subject mapping calls, got %d", smCalls)
	}

	// Verify hierarchy selector (no []).
	smHierarchy := reqs[2]
	cond := extractConditionSet(t, smHierarchy.Body)
	if cond.selector != ".classification_level" {
		t.Errorf("hierarchy selector: expected '.classification_level', got %q", cond.selector)
	}

	// Verify allOf selector (with []).
	smAllOf := reqs[5]
	cond2 := extractConditionSet(t, smAllOf.Body)
	if cond2.selector != ".sci_control[]" {
		t.Errorf("allOf selector: expected '.sci_control[]', got %q", cond2.selector)
	}

	// Verify anyOf selector (with []).
	smAnyOf := reqs[7]
	cond3 := extractConditionSet(t, smAnyOf.Body)
	if cond3.selector != ".releasable_to[]" {
		t.Errorf("anyOf selector: expected '.releasable_to[]', got %q", cond3.selector)
	}
}

func TestProvisionIdempotent(t *testing.T) {
	capture := &requestCapture{}

	// Server returns "already exists" for namespace, then success for list.
	callCount := 0
	var mu sync.Mutex

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make(map[string]interface{})
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("failed to decode body: %v", err)
		}
		capture.add(r.URL.Path, body, r.Header)

		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/policy.namespaces.NamespaceService/CreateNamespace":
			// Return "already exists".
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"code":"already_exists","message":"namespace already exists"}`))

		case "/policy.namespaces.NamespaceService/ListNamespaces":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"namespaces":[{"id":"ns-existing","name":"tdflite.local"}]}`))

		case "/policy.attributes.AttributesService/CreateAttribute":
			mu.Lock()
			idx := callCount
			callCount++
			mu.Unlock()

			if idx == 0 {
				// First attribute succeeds.
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"attribute":{"id":"attr-1","values":[{"id":"val-1","value":"public"}]}}`))
			} else {
				// Second attribute already exists.
				w.WriteHeader(http.StatusConflict)
				_, _ = w.Write([]byte(`{"code":"already_exists","message":"attribute already exists"}`))
			}

		case "/policy.subjectmapping.SubjectMappingService/CreateSubjectMapping":
			// Subject mapping already exists.
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"code":"already_exists","message":"subject mapping already exists"}`))

		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	bundle := &policybundle.Bundle{
		Namespace: "tdflite.local",
		Attributes: []policybundle.Attribute{
			{Name: "visibility", Rule: policybundle.RuleAnyOf, Values: []string{"PUBLIC"}},
			{Name: "dept", Rule: policybundle.RuleAllOf, Values: []string{"ENG"}},
		},
		Identities: map[string]policybundle.Identity{"admin": {Admin: true}},
	}

	err := Provision(context.Background(), bundle, srv.URL, "test-token")
	if err != nil {
		t.Fatalf("expected no error for idempotent provision, got: %v", err)
	}

	// Verify the namespace was looked up via ListNamespaces after "already exists".
	reqs := capture.all()
	foundList := false
	for _, r := range reqs {
		if r.Path == "/policy.namespaces.NamespaceService/ListNamespaces" {
			foundList = true
			break
		}
	}
	if !foundList {
		t.Error("expected ListNamespaces call after 'already exists', but not found")
	}
}

func TestRuleTypeMapping(t *testing.T) {
	tests := []struct {
		rule     policybundle.AttributeRule
		expected string
	}{
		{policybundle.RuleHierarchy, RuleHierarchy},
		{policybundle.RuleAllOf, RuleAllOf},
		{policybundle.RuleAnyOf, RuleAnyOf},
	}

	for _, tt := range tests {
		t.Run(string(tt.rule), func(t *testing.T) {
			result, err := MapRuleType(tt.rule)
			if err != nil {
				t.Fatalf("MapRuleType(%q) returned error: %v", tt.rule, err)
			}
			if result != tt.expected {
				t.Errorf("MapRuleType(%q) = %q, want %q", tt.rule, result, tt.expected)
			}
		})
	}

	// Test unknown rule.
	t.Run("unknown", func(t *testing.T) {
		_, err := MapRuleType("bogus")
		if err == nil {
			t.Error("expected error for unknown rule type, got nil")
		}
	})
}

// conditionSetInfo holds extracted values from a subject mapping request body.
type conditionSetInfo struct {
	selector string
	operator string
	values   []string
}

// extractConditionSet navigates the nested subject mapping request body to
// extract the selector, operator, and values from the first condition.
func extractConditionSet(t *testing.T, body map[string]interface{}) conditionSetInfo {
	t.Helper()

	condSet, ok := body["newSubjectConditionSet"].(map[string]interface{})
	if !ok {
		t.Fatal("missing newSubjectConditionSet")
	}

	subjectSets, ok := condSet["subjectSets"].([]interface{})
	if !ok || len(subjectSets) == 0 {
		t.Fatal("missing or empty subjectSets")
	}

	ss, ok := subjectSets[0].(map[string]interface{})
	if !ok {
		t.Fatal("subjectSets[0] not a map")
	}

	groups, ok := ss["conditionGroups"].([]interface{})
	if !ok || len(groups) == 0 {
		t.Fatal("missing or empty conditionGroups")
	}

	group, ok := groups[0].(map[string]interface{})
	if !ok {
		t.Fatal("conditionGroups[0] not a map")
	}

	conditions, ok := group["conditions"].([]interface{})
	if !ok || len(conditions) == 0 {
		t.Fatal("missing or empty conditions")
	}

	cond, ok := conditions[0].(map[string]interface{})
	if !ok {
		t.Fatal("conditions[0] not a map")
	}

	info := conditionSetInfo{}
	info.selector, _ = cond["subjectExternalSelectorValue"].(string)
	info.operator, _ = cond["operator"].(string)

	if vals, ok := cond["subjectExternalValues"].([]interface{}); ok {
		for _, v := range vals {
			if s, ok := v.(string); ok {
				info.values = append(info.values, s)
			}
		}
	}

	return info
}
