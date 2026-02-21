// Package memory provides an in-memory implementation of the store interfaces.
//
// Data lives only in process memory. For persistence across restarts,
// use the jsonfile store or wrap this with a persistence layer.
package memory

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/willnorris/tdflite/internal/store"
)

// Store is an in-memory implementation of store.Store.
type Store struct {
	policy   *policyStore
	key      *keyStore
	identity *identityStore
}

// New creates a new in-memory store.
func New() store.Store {
	return &Store{
		policy:   newPolicyStore(),
		key:      newKeyStore(),
		identity: newIdentityStore(),
	}
}

func (s *Store) PolicyStore() store.PolicyStore     { return s.policy }
func (s *Store) KeyStore() store.KeyStore           { return s.key }
func (s *Store) IdentityStore() store.IdentityStore { return s.identity }
func (s *Store) Close() error                       { return nil }

// --- Policy Store ---

type policyStore struct {
	mu                   sync.RWMutex
	namespaces           map[string]*store.Namespace
	attributeDefinitions map[string]*store.AttributeDefinition
	attributeValues      map[string]*store.AttributeValue
	subjectMappings      map[string]*store.SubjectMapping
	subjectConditionSets map[string]*store.SubjectConditionSet
	resourceMappings     map[string]*store.ResourceMapping
}

func newPolicyStore() *policyStore {
	return &policyStore{
		namespaces:           make(map[string]*store.Namespace),
		attributeDefinitions: make(map[string]*store.AttributeDefinition),
		attributeValues:      make(map[string]*store.AttributeValue),
		subjectMappings:      make(map[string]*store.SubjectMapping),
		subjectConditionSets: make(map[string]*store.SubjectConditionSet),
		resourceMappings:     make(map[string]*store.ResourceMapping),
	}
}

func (ps *policyStore) CreateNamespace(_ context.Context, ns *store.Namespace) error {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	if _, exists := ps.namespaces[ns.ID]; exists {
		return fmt.Errorf("namespace %s already exists", ns.ID)
	}
	now := time.Now()
	ns.CreatedAt = now
	ns.UpdatedAt = now
	ps.namespaces[ns.ID] = ns
	return nil
}

func (ps *policyStore) GetNamespace(_ context.Context, id string) (*store.Namespace, error) {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	ns, ok := ps.namespaces[id]
	if !ok {
		return nil, fmt.Errorf("namespace %s not found", id)
	}
	return ns, nil
}

func (ps *policyStore) ListNamespaces(_ context.Context) ([]*store.Namespace, error) {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	result := make([]*store.Namespace, 0, len(ps.namespaces))
	for _, ns := range ps.namespaces {
		result = append(result, ns)
	}
	return result, nil
}

func (ps *policyStore) UpdateNamespace(_ context.Context, ns *store.Namespace) error {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	if _, exists := ps.namespaces[ns.ID]; !exists {
		return fmt.Errorf("namespace %s not found", ns.ID)
	}
	ns.UpdatedAt = time.Now()
	ps.namespaces[ns.ID] = ns
	return nil
}

func (ps *policyStore) DeactivateNamespace(_ context.Context, id string) error {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	ns, ok := ps.namespaces[id]
	if !ok {
		return fmt.Errorf("namespace %s not found", id)
	}
	ns.Active = false
	ns.UpdatedAt = time.Now()
	// Cascade deactivation to attribute definitions and values.
	for _, def := range ps.attributeDefinitions {
		if def.NamespaceID == id {
			def.Active = false
			def.UpdatedAt = time.Now()
			for _, val := range ps.attributeValues {
				if val.AttributeDefinitionID == def.ID {
					val.Active = false
					val.UpdatedAt = time.Now()
				}
			}
		}
	}
	return nil
}

func (ps *policyStore) CreateAttributeDefinition(_ context.Context, def *store.AttributeDefinition) error {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	if _, exists := ps.attributeDefinitions[def.ID]; exists {
		return fmt.Errorf("attribute definition %s already exists", def.ID)
	}
	now := time.Now()
	def.CreatedAt = now
	def.UpdatedAt = now
	ps.attributeDefinitions[def.ID] = def
	return nil
}

func (ps *policyStore) GetAttributeDefinition(_ context.Context, id string) (*store.AttributeDefinition, error) {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	def, ok := ps.attributeDefinitions[id]
	if !ok {
		return nil, fmt.Errorf("attribute definition %s not found", id)
	}
	return def, nil
}

func (ps *policyStore) ListAttributeDefinitions(_ context.Context, namespaceID string) ([]*store.AttributeDefinition, error) {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	var result []*store.AttributeDefinition
	for _, def := range ps.attributeDefinitions {
		if namespaceID == "" || def.NamespaceID == namespaceID {
			result = append(result, def)
		}
	}
	return result, nil
}

func (ps *policyStore) UpdateAttributeDefinition(_ context.Context, def *store.AttributeDefinition) error {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	if _, exists := ps.attributeDefinitions[def.ID]; !exists {
		return fmt.Errorf("attribute definition %s not found", def.ID)
	}
	def.UpdatedAt = time.Now()
	ps.attributeDefinitions[def.ID] = def
	return nil
}

func (ps *policyStore) DeactivateAttributeDefinition(_ context.Context, id string) error {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	def, ok := ps.attributeDefinitions[id]
	if !ok {
		return fmt.Errorf("attribute definition %s not found", id)
	}
	def.Active = false
	def.UpdatedAt = time.Now()
	for _, val := range ps.attributeValues {
		if val.AttributeDefinitionID == id {
			val.Active = false
			val.UpdatedAt = time.Now()
		}
	}
	return nil
}

func (ps *policyStore) CreateAttributeValue(_ context.Context, val *store.AttributeValue) error {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	if _, exists := ps.attributeValues[val.ID]; exists {
		return fmt.Errorf("attribute value %s already exists", val.ID)
	}
	now := time.Now()
	val.CreatedAt = now
	val.UpdatedAt = now
	ps.attributeValues[val.ID] = val
	return nil
}

func (ps *policyStore) GetAttributeValue(_ context.Context, id string) (*store.AttributeValue, error) {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	val, ok := ps.attributeValues[id]
	if !ok {
		return nil, fmt.Errorf("attribute value %s not found", id)
	}
	return val, nil
}

func (ps *policyStore) ListAttributeValues(_ context.Context, definitionID string) ([]*store.AttributeValue, error) {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	var result []*store.AttributeValue
	for _, val := range ps.attributeValues {
		if definitionID == "" || val.AttributeDefinitionID == definitionID {
			result = append(result, val)
		}
	}
	return result, nil
}

func (ps *policyStore) UpdateAttributeValue(_ context.Context, val *store.AttributeValue) error {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	if _, exists := ps.attributeValues[val.ID]; !exists {
		return fmt.Errorf("attribute value %s not found", val.ID)
	}
	val.UpdatedAt = time.Now()
	ps.attributeValues[val.ID] = val
	return nil
}

func (ps *policyStore) DeactivateAttributeValue(_ context.Context, id string) error {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	val, ok := ps.attributeValues[id]
	if !ok {
		return fmt.Errorf("attribute value %s not found", id)
	}
	val.Active = false
	val.UpdatedAt = time.Now()
	return nil
}

func (ps *policyStore) CreateSubjectMapping(_ context.Context, sm *store.SubjectMapping) error {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	if _, exists := ps.subjectMappings[sm.ID]; exists {
		return fmt.Errorf("subject mapping %s already exists", sm.ID)
	}
	now := time.Now()
	sm.CreatedAt = now
	sm.UpdatedAt = now
	ps.subjectMappings[sm.ID] = sm
	return nil
}

func (ps *policyStore) GetSubjectMapping(_ context.Context, id string) (*store.SubjectMapping, error) {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	sm, ok := ps.subjectMappings[id]
	if !ok {
		return nil, fmt.Errorf("subject mapping %s not found", id)
	}
	return sm, nil
}

func (ps *policyStore) ListSubjectMappings(_ context.Context) ([]*store.SubjectMapping, error) {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	result := make([]*store.SubjectMapping, 0, len(ps.subjectMappings))
	for _, sm := range ps.subjectMappings {
		result = append(result, sm)
	}
	return result, nil
}

func (ps *policyStore) UpdateSubjectMapping(_ context.Context, sm *store.SubjectMapping) error {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	if _, exists := ps.subjectMappings[sm.ID]; !exists {
		return fmt.Errorf("subject mapping %s not found", sm.ID)
	}
	sm.UpdatedAt = time.Now()
	ps.subjectMappings[sm.ID] = sm
	return nil
}

func (ps *policyStore) DeleteSubjectMapping(_ context.Context, id string) error {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	if _, exists := ps.subjectMappings[id]; !exists {
		return fmt.Errorf("subject mapping %s not found", id)
	}
	delete(ps.subjectMappings, id)
	return nil
}

func (ps *policyStore) CreateSubjectConditionSet(_ context.Context, scs *store.SubjectConditionSet) error {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	if _, exists := ps.subjectConditionSets[scs.ID]; exists {
		return fmt.Errorf("subject condition set %s already exists", scs.ID)
	}
	now := time.Now()
	scs.CreatedAt = now
	scs.UpdatedAt = now
	ps.subjectConditionSets[scs.ID] = scs
	return nil
}

func (ps *policyStore) GetSubjectConditionSet(_ context.Context, id string) (*store.SubjectConditionSet, error) {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	scs, ok := ps.subjectConditionSets[id]
	if !ok {
		return nil, fmt.Errorf("subject condition set %s not found", id)
	}
	return scs, nil
}

func (ps *policyStore) ListSubjectConditionSets(_ context.Context) ([]*store.SubjectConditionSet, error) {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	result := make([]*store.SubjectConditionSet, 0, len(ps.subjectConditionSets))
	for _, scs := range ps.subjectConditionSets {
		result = append(result, scs)
	}
	return result, nil
}

func (ps *policyStore) UpdateSubjectConditionSet(_ context.Context, scs *store.SubjectConditionSet) error {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	if _, exists := ps.subjectConditionSets[scs.ID]; !exists {
		return fmt.Errorf("subject condition set %s not found", scs.ID)
	}
	scs.UpdatedAt = time.Now()
	ps.subjectConditionSets[scs.ID] = scs
	return nil
}

func (ps *policyStore) DeleteSubjectConditionSet(_ context.Context, id string) error {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	if _, exists := ps.subjectConditionSets[id]; !exists {
		return fmt.Errorf("subject condition set %s not found", id)
	}
	delete(ps.subjectConditionSets, id)
	return nil
}

func (ps *policyStore) CreateResourceMapping(_ context.Context, rm *store.ResourceMapping) error {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	if _, exists := ps.resourceMappings[rm.ID]; exists {
		return fmt.Errorf("resource mapping %s already exists", rm.ID)
	}
	now := time.Now()
	rm.CreatedAt = now
	rm.UpdatedAt = now
	ps.resourceMappings[rm.ID] = rm
	return nil
}

func (ps *policyStore) GetResourceMapping(_ context.Context, id string) (*store.ResourceMapping, error) {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	rm, ok := ps.resourceMappings[id]
	if !ok {
		return nil, fmt.Errorf("resource mapping %s not found", id)
	}
	return rm, nil
}

func (ps *policyStore) ListResourceMappings(_ context.Context) ([]*store.ResourceMapping, error) {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	result := make([]*store.ResourceMapping, 0, len(ps.resourceMappings))
	for _, rm := range ps.resourceMappings {
		result = append(result, rm)
	}
	return result, nil
}

func (ps *policyStore) UpdateResourceMapping(_ context.Context, rm *store.ResourceMapping) error {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	if _, exists := ps.resourceMappings[rm.ID]; !exists {
		return fmt.Errorf("resource mapping %s not found", rm.ID)
	}
	rm.UpdatedAt = time.Now()
	ps.resourceMappings[rm.ID] = rm
	return nil
}

func (ps *policyStore) DeleteResourceMapping(_ context.Context, id string) error {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	if _, exists := ps.resourceMappings[id]; !exists {
		return fmt.Errorf("resource mapping %s not found", id)
	}
	delete(ps.resourceMappings, id)
	return nil
}

// --- Key Store ---

type keyStore struct {
	mu              sync.RWMutex
	kasRegistrations map[string]*store.KASRegistration
	keys            map[string]*store.RegisteredKey
	grants          map[string]*store.KeyAccessGrant
}

func newKeyStore() *keyStore {
	return &keyStore{
		kasRegistrations: make(map[string]*store.KASRegistration),
		keys:            make(map[string]*store.RegisteredKey),
		grants:          make(map[string]*store.KeyAccessGrant),
	}
}

func (ks *keyStore) CreateKASRegistration(_ context.Context, kas *store.KASRegistration) error {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	if _, exists := ks.kasRegistrations[kas.ID]; exists {
		return fmt.Errorf("KAS registration %s already exists", kas.ID)
	}
	now := time.Now()
	kas.CreatedAt = now
	kas.UpdatedAt = now
	ks.kasRegistrations[kas.ID] = kas
	return nil
}

func (ks *keyStore) GetKASRegistration(_ context.Context, id string) (*store.KASRegistration, error) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	kas, ok := ks.kasRegistrations[id]
	if !ok {
		return nil, fmt.Errorf("KAS registration %s not found", id)
	}
	return kas, nil
}

func (ks *keyStore) ListKASRegistrations(_ context.Context) ([]*store.KASRegistration, error) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	result := make([]*store.KASRegistration, 0, len(ks.kasRegistrations))
	for _, kas := range ks.kasRegistrations {
		result = append(result, kas)
	}
	return result, nil
}

func (ks *keyStore) UpdateKASRegistration(_ context.Context, kas *store.KASRegistration) error {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	if _, exists := ks.kasRegistrations[kas.ID]; !exists {
		return fmt.Errorf("KAS registration %s not found", kas.ID)
	}
	kas.UpdatedAt = time.Now()
	ks.kasRegistrations[kas.ID] = kas
	return nil
}

func (ks *keyStore) DeleteKASRegistration(_ context.Context, id string) error {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	if _, exists := ks.kasRegistrations[id]; !exists {
		return fmt.Errorf("KAS registration %s not found", id)
	}
	delete(ks.kasRegistrations, id)
	return nil
}

func (ks *keyStore) CreateKey(_ context.Context, key *store.RegisteredKey) error {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	if _, exists := ks.keys[key.ID]; exists {
		return fmt.Errorf("key %s already exists", key.ID)
	}
	now := time.Now()
	key.CreatedAt = now
	key.UpdatedAt = now
	ks.keys[key.ID] = key
	return nil
}

func (ks *keyStore) GetKey(_ context.Context, id string) (*store.RegisteredKey, error) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	key, ok := ks.keys[id]
	if !ok {
		return nil, fmt.Errorf("key %s not found", id)
	}
	return key, nil
}

func (ks *keyStore) ListKeys(_ context.Context, kasID string) ([]*store.RegisteredKey, error) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	var result []*store.RegisteredKey
	for _, key := range ks.keys {
		if kasID == "" || key.KASServerID == kasID {
			result = append(result, key)
		}
	}
	return result, nil
}

func (ks *keyStore) UpdateKey(_ context.Context, key *store.RegisteredKey) error {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	if _, exists := ks.keys[key.ID]; !exists {
		return fmt.Errorf("key %s not found", key.ID)
	}
	key.UpdatedAt = time.Now()
	ks.keys[key.ID] = key
	return nil
}

func (ks *keyStore) DeleteKey(_ context.Context, id string) error {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	if _, exists := ks.keys[id]; !exists {
		return fmt.Errorf("key %s not found", id)
	}
	delete(ks.keys, id)
	return nil
}

func (ks *keyStore) CreateKeyAccessGrant(_ context.Context, grant *store.KeyAccessGrant) error {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	if _, exists := ks.grants[grant.ID]; exists {
		return fmt.Errorf("key access grant %s already exists", grant.ID)
	}
	ks.grants[grant.ID] = grant
	return nil
}

func (ks *keyStore) ListKeyAccessGrants(_ context.Context, keyID string) ([]*store.KeyAccessGrant, error) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	var result []*store.KeyAccessGrant
	for _, grant := range ks.grants {
		if keyID == "" || grant.KeyID == keyID {
			result = append(result, grant)
		}
	}
	return result, nil
}

func (ks *keyStore) DeleteKeyAccessGrant(_ context.Context, id string) error {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	if _, exists := ks.grants[id]; !exists {
		return fmt.Errorf("key access grant %s not found", id)
	}
	delete(ks.grants, id)
	return nil
}

// --- Identity Store ---

type identityStore struct {
	mu         sync.RWMutex
	identities map[string]*store.Identity
}

func newIdentityStore() *identityStore {
	return &identityStore{
		identities: make(map[string]*store.Identity),
	}
}

func (is *identityStore) CreateIdentity(_ context.Context, id *store.Identity) error {
	is.mu.Lock()
	defer is.mu.Unlock()
	if _, exists := is.identities[id.ID]; exists {
		return fmt.Errorf("identity %s already exists", id.ID)
	}
	now := time.Now()
	id.CreatedAt = now
	id.UpdatedAt = now
	is.identities[id.ID] = id
	return nil
}

func (is *identityStore) GetIdentity(_ context.Context, id string) (*store.Identity, error) {
	is.mu.RLock()
	defer is.mu.RUnlock()
	identity, ok := is.identities[id]
	if !ok {
		return nil, fmt.Errorf("identity %s not found", id)
	}
	return identity, nil
}

func (is *identityStore) GetIdentityBySubject(_ context.Context, subject string) (*store.Identity, error) {
	is.mu.RLock()
	defer is.mu.RUnlock()
	for _, identity := range is.identities {
		if identity.Subject == subject {
			return identity, nil
		}
	}
	return nil, fmt.Errorf("identity with subject %s not found", subject)
}

func (is *identityStore) GetIdentityByClientID(_ context.Context, clientID string) (*store.Identity, error) {
	is.mu.RLock()
	defer is.mu.RUnlock()
	for _, identity := range is.identities {
		if identity.ClientID == clientID {
			return identity, nil
		}
	}
	return nil, fmt.Errorf("identity with client_id %s not found", clientID)
}

func (is *identityStore) ListIdentities(_ context.Context) ([]*store.Identity, error) {
	is.mu.RLock()
	defer is.mu.RUnlock()
	result := make([]*store.Identity, 0, len(is.identities))
	for _, identity := range is.identities {
		result = append(result, identity)
	}
	return result, nil
}

func (is *identityStore) UpdateIdentity(_ context.Context, id *store.Identity) error {
	is.mu.Lock()
	defer is.mu.Unlock()
	if _, exists := is.identities[id.ID]; !exists {
		return fmt.Errorf("identity %s not found", id.ID)
	}
	id.UpdatedAt = time.Now()
	is.identities[id.ID] = id
	return nil
}

func (is *identityStore) DeleteIdentity(_ context.Context, id string) error {
	is.mu.Lock()
	defer is.mu.Unlock()
	if _, exists := is.identities[id]; !exists {
		return fmt.Errorf("identity %s not found", id)
	}
	delete(is.identities, id)
	return nil
}
