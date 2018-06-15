package fakedatastore

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	radix "github.com/armon/go-radix"
	"github.com/golang/protobuf/proto"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
	uuid "github.com/satori/go.uuid"
	"github.com/spiffe/spire/pkg/common/selector"
	"github.com/spiffe/spire/proto/common"
	spi "github.com/spiffe/spire/proto/common/plugin"
	"github.com/spiffe/spire/proto/server/datastore"
)

const (
	selectorKeySeparator = '|'
)

var (
	ErrBundleAlreadyExists               = errors.New("bundle already exists")
	ErrNoSuchBundle                      = errors.New("no such bundle")
	ErrAttestedNodeEntryAlreadyExists    = errors.New("attested node entry already exists")
	ErrNoSuchAttestedNodeEntry           = errors.New("no such attested node entry")
	ErrNodeResolverMapEntryAlreadyExists = errors.New("node resolver map entry already exists")
	ErrNoSuchNodeResolverMapEntry        = errors.New("no such node resolver map entry")
	ErrNoSuchRegistrationEntry           = errors.New("no such registration entry")
	ErrNoSuchToken                       = errors.New("no such token")
	ErrTokenAlreadyExists                = errors.New("token already exists")
)

type FakeDataStore struct {
	mu sync.Mutex

	bundles                map[string]*datastore.Bundle
	attestedNodeEntries    map[string]*datastore.AttestedNodeEntry
	nodeResolverMapEntries *radix.Tree
	registrationEntries    map[string]*datastore.RegistrationEntry
	tokens                 map[string]*datastore.JoinToken
}

var _ datastore.DataStore = (*FakeDataStore)(nil)

func New() *FakeDataStore {
	return &FakeDataStore{
		bundles:                make(map[string]*datastore.Bundle),
		attestedNodeEntries:    make(map[string]*datastore.AttestedNodeEntry),
		nodeResolverMapEntries: radix.New(),
		registrationEntries:    make(map[string]*datastore.RegistrationEntry),
		tokens:                 make(map[string]*datastore.JoinToken),
	}
}

// CreateBundle stores the given bundle
func (s *FakeDataStore) CreateBundle(ctx context.Context, req *datastore.Bundle) (*datastore.Bundle, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.bundles[req.TrustDomain]; ok {
		return nil, ErrBundleAlreadyExists
	}

	s.bundles[req.TrustDomain] = cloneBundle(req)
	return cloneBundle(req), nil
}

// UpdateBundle updates an existing bundle with the given CAs. Overwrites any
// existing certificates.
func (s *FakeDataStore) UpdateBundle(ctx context.Context, req *datastore.Bundle) (*datastore.Bundle, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.bundles[req.TrustDomain] = cloneBundle(req)
	return cloneBundle(req), nil
}

// AppendBundle adds the specified CA certificates to an existing bundle. If no bundle exists for the
// specified trust domain, create one. Returns the entirety.
func (s *FakeDataStore) AppendBundle(ctx context.Context, req *datastore.Bundle) (*datastore.Bundle, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	bundle, ok := s.bundles[req.TrustDomain]
	if !ok {
		bundle = &datastore.Bundle{
			TrustDomain: req.TrustDomain,
		}
		s.bundles[req.TrustDomain] = bundle
	}

	bundle.CaCerts = append(bundle.CaCerts, cloneBundle(req).CaCerts...)
	return cloneBundle(bundle), nil
}

// DeleteBundle deletes the bundle with the matching TrustDomain. Any CACert data passed is ignored.
func (s *FakeDataStore) DeleteBundle(ctx context.Context, req *datastore.Bundle) (*datastore.Bundle, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	bundle, ok := s.bundles[req.TrustDomain]
	if !ok {
		return nil, ErrNoSuchBundle
	}
	delete(s.bundles, req.TrustDomain)

	return cloneBundle(bundle), nil
}

// FetchBundle returns the bundle matching the specified Trust Domain.
func (s *FakeDataStore) FetchBundle(ctx context.Context, req *datastore.Bundle) (*datastore.Bundle, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	bundle, ok := s.bundles[req.TrustDomain]
	if !ok {
		return nil, ErrNoSuchBundle
	}

	return cloneBundle(bundle), nil
}

// ListBundles can be used to fetch all existing bundles.
func (s *FakeDataStore) ListBundles(ctx context.Context, req *common.Empty) (*datastore.Bundles, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	bundles := new(datastore.Bundles)
	for _, bundle := range s.bundles {
		bundles.Bundles = append(bundles.Bundles, cloneBundle(bundle))
	}

	return bundles, nil
}

func (s *FakeDataStore) CreateAttestedNodeEntry(ctx context.Context,
	req *datastore.CreateAttestedNodeEntryRequest) (*datastore.CreateAttestedNodeEntryResponse, error) {

	s.mu.Lock()
	defer s.mu.Unlock()

	entry := req.AttestedNodeEntry

	if _, ok := s.attestedNodeEntries[entry.BaseSpiffeId]; ok {
		return nil, ErrAttestedNodeEntryAlreadyExists
	}

	s.attestedNodeEntries[entry.BaseSpiffeId] = cloneAttestedNodeEntry(entry)
	return &datastore.CreateAttestedNodeEntryResponse{
		AttestedNodeEntry: cloneAttestedNodeEntry(entry),
	}, nil
}

func (s *FakeDataStore) FetchAttestedNodeEntry(ctx context.Context,
	req *datastore.FetchAttestedNodeEntryRequest) (*datastore.FetchAttestedNodeEntryResponse, error) {

	s.mu.Lock()
	defer s.mu.Unlock()

	resp := new(datastore.FetchAttestedNodeEntryResponse)
	bundle, ok := s.attestedNodeEntries[req.BaseSpiffeId]
	if !ok {
		return resp, nil
	}
	resp.AttestedNodeEntry = cloneAttestedNodeEntry(bundle)

	return resp, nil
}

func (s *FakeDataStore) FetchStaleNodeEntries(ctx context.Context,
	req *datastore.FetchStaleNodeEntriesRequest) (*datastore.FetchStaleNodeEntriesResponse, error) {

	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()

	resp := new(datastore.FetchStaleNodeEntriesResponse)
	for _, attestedNodeEntry := range s.attestedNodeEntries {
		certExpirationDate, err := time.Parse(datastore.TimeFormat, attestedNodeEntry.CertExpirationDate)
		if err == nil && !certExpirationDate.Before(now) {
			continue
		}
		resp.AttestedNodeEntryList = append(resp.AttestedNodeEntryList,
			cloneAttestedNodeEntry(attestedNodeEntry))
	}

	return resp, nil
}

func (s *FakeDataStore) UpdateAttestedNodeEntry(ctx context.Context,
	req *datastore.UpdateAttestedNodeEntryRequest) (*datastore.UpdateAttestedNodeEntryResponse, error) {

	s.mu.Lock()
	defer s.mu.Unlock()

	attestedNodeEntry, ok := s.attestedNodeEntries[req.BaseSpiffeId]
	if !ok {
		return nil, ErrNoSuchAttestedNodeEntry
	}
	attestedNodeEntry.CertSerialNumber = req.CertSerialNumber
	attestedNodeEntry.CertExpirationDate = req.CertExpirationDate

	return &datastore.UpdateAttestedNodeEntryResponse{
		AttestedNodeEntry: cloneAttestedNodeEntry(attestedNodeEntry),
	}, nil
}

func (s *FakeDataStore) DeleteAttestedNodeEntry(ctx context.Context,
	req *datastore.DeleteAttestedNodeEntryRequest) (*datastore.DeleteAttestedNodeEntryResponse, error) {

	s.mu.Lock()
	defer s.mu.Unlock()

	attestedNodeEntry, ok := s.attestedNodeEntries[req.BaseSpiffeId]
	if !ok {
		return nil, ErrNoSuchAttestedNodeEntry
	}
	delete(s.attestedNodeEntries, req.BaseSpiffeId)

	return &datastore.DeleteAttestedNodeEntryResponse{
		AttestedNodeEntry: cloneAttestedNodeEntry(attestedNodeEntry),
	}, nil
}

func (s *FakeDataStore) CreateNodeResolverMapEntry(ctx context.Context,
	req *datastore.CreateNodeResolverMapEntryRequest) (*datastore.CreateNodeResolverMapEntryResponse, error) {

	s.mu.Lock()
	defer s.mu.Unlock()

	entry := req.NodeResolverMapEntry
	key := nodeResolverMapEntryKey(entry)

	if _, ok := s.nodeResolverMapEntries.Get(key); ok {
		return nil, ErrNodeResolverMapEntryAlreadyExists
	}

	s.nodeResolverMapEntries.Insert(key, cloneNodeResolverMapEntry(entry))
	return &datastore.CreateNodeResolverMapEntryResponse{
		NodeResolverMapEntry: cloneNodeResolverMapEntry(entry),
	}, nil
}

func (s *FakeDataStore) FetchNodeResolverMapEntry(ctx context.Context,
	req *datastore.FetchNodeResolverMapEntryRequest) (*datastore.FetchNodeResolverMapEntryResponse, error) {

	s.mu.Lock()
	defer s.mu.Unlock()

	s.nodeResolverMapEntries.Walk(func(key string, v interface{}) bool {
		return false
	})
	resp := new(datastore.FetchNodeResolverMapEntryResponse)
	s.nodeResolverMapEntries.WalkPrefix(
		nodeResolverMapEntrySpiffeIDPrefix(req.BaseSpiffeId),
		func(key string, v interface{}) bool {
			resp.NodeResolverMapEntryList = append(
				resp.NodeResolverMapEntryList,
				cloneNodeResolverMapEntry(v.(*datastore.NodeResolverMapEntry)))
			return false
		})

	return resp, nil
}

func (s *FakeDataStore) DeleteNodeResolverMapEntry(ctx context.Context,
	req *datastore.DeleteNodeResolverMapEntryRequest) (*datastore.DeleteNodeResolverMapEntryResponse, error) {

	s.mu.Lock()
	defer s.mu.Unlock()

	resp := new(datastore.DeleteNodeResolverMapEntryResponse)
	if req.NodeResolverMapEntry.Selector != nil {
		key := nodeResolverMapEntryKey(req.NodeResolverMapEntry)
		v, ok := s.nodeResolverMapEntries.Get(key)
		if !ok {
			return nil, ErrNoSuchNodeResolverMapEntry
		}
		resp.NodeResolverMapEntryList = append(
			resp.NodeResolverMapEntryList,
			cloneNodeResolverMapEntry(v.(*datastore.NodeResolverMapEntry)))
	} else {
		prefix := nodeResolverMapEntrySpiffeIDPrefix(req.NodeResolverMapEntry.BaseSpiffeId)
		s.nodeResolverMapEntries.WalkPrefix(prefix,
			func(key string, v interface{}) bool {
				resp.NodeResolverMapEntryList = append(
					resp.NodeResolverMapEntryList,
					cloneNodeResolverMapEntry(v.(*datastore.NodeResolverMapEntry)))
				return true
			})
		s.nodeResolverMapEntries.DeletePrefix(prefix)
	}

	return resp, nil
}

func (FakeDataStore) RectifyNodeResolverMapEntries(ctx context.Context,
	req *datastore.RectifyNodeResolverMapEntriesRequest) (*datastore.RectifyNodeResolverMapEntriesResponse, error) {
	return &datastore.RectifyNodeResolverMapEntriesResponse{}, errors.New("Not Implemented")
}

func (s *FakeDataStore) CreateRegistrationEntry(ctx context.Context,
	request *datastore.CreateRegistrationEntryRequest) (*datastore.CreateRegistrationEntryResponse, error) {

	s.mu.Lock()
	defer s.mu.Unlock()

	entryID, err := newRegistrationEntryID()
	if err != nil {
		return nil, err
	}

	entry := cloneRegistrationEntry(request.RegisteredEntry)
	entry.EntryId = entryID
	s.registrationEntries[entryID] = entry

	return &datastore.CreateRegistrationEntryResponse{
		RegisteredEntryId: entryID,
	}, nil
}

func (s *FakeDataStore) FetchRegistrationEntry(ctx context.Context,
	request *datastore.FetchRegistrationEntryRequest) (*datastore.FetchRegistrationEntryResponse, error) {

	s.mu.Lock()
	defer s.mu.Unlock()

	resp := new(datastore.FetchRegistrationEntryResponse)
	entry, ok := s.registrationEntries[request.RegisteredEntryId]
	if !ok {
		return resp, nil
	}
	resp.RegisteredEntry = cloneRegistrationEntry(entry)

	return resp, nil
}

func (s *FakeDataStore) FetchRegistrationEntries(ctx context.Context,
	request *common.Empty) (*datastore.FetchRegistrationEntriesResponse, error) {

	s.mu.Lock()
	defer s.mu.Unlock()

	entries := new(common.RegistrationEntries)
	for _, entry := range s.registrationEntries {
		entries.Entries = append(entries.Entries, cloneRegistrationEntry(entry))
	}

	// TODO: do we really need to sort the entries?

	return &datastore.FetchRegistrationEntriesResponse{
		RegisteredEntries: entries,
	}, nil
}

func (s FakeDataStore) UpdateRegistrationEntry(ctx context.Context,
	request *datastore.UpdateRegistrationEntryRequest) (*datastore.UpdateRegistrationEntryResponse, error) {

	s.mu.Lock()
	defer s.mu.Unlock()

	_, ok := s.registrationEntries[request.RegisteredEntryId]
	if !ok {
		return nil, ErrNoSuchRegistrationEntry
	}

	entry := cloneRegistrationEntry(request.RegisteredEntry)
	entry.EntryId = request.RegisteredEntryId
	s.registrationEntries[request.RegisteredEntryId] = entry

	return &datastore.UpdateRegistrationEntryResponse{
		RegisteredEntry: cloneRegistrationEntry(entry),
	}, nil
}

func (s *FakeDataStore) DeleteRegistrationEntry(ctx context.Context,
	request *datastore.DeleteRegistrationEntryRequest) (*datastore.DeleteRegistrationEntryResponse, error) {

	s.mu.Lock()
	defer s.mu.Unlock()

	registrationEntry, ok := s.registrationEntries[request.RegisteredEntryId]
	if !ok {
		return nil, ErrNoSuchRegistrationEntry
	}
	delete(s.registrationEntries, request.RegisteredEntryId)

	return &datastore.DeleteRegistrationEntryResponse{
		RegisteredEntry: cloneRegistrationEntry(registrationEntry),
	}, nil
}

func (s *FakeDataStore) ListParentIDEntries(ctx context.Context,
	request *datastore.ListParentIDEntriesRequest) (response *datastore.ListParentIDEntriesResponse, err error) {

	s.mu.Lock()
	defer s.mu.Unlock()

	var registeredEntryList []*common.RegistrationEntry
	for _, registrationEntry := range s.registrationEntries {
		if registrationEntry.ParentId == request.ParentId {
			registeredEntryList = append(registeredEntryList, cloneRegistrationEntry(registrationEntry))
		}
	}

	return &datastore.ListParentIDEntriesResponse{
		RegisteredEntryList: registeredEntryList,
	}, nil
}

func (s *FakeDataStore) ListSelectorEntries(ctx context.Context,
	request *datastore.ListSelectorEntriesRequest) (*datastore.ListSelectorEntriesResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return &datastore.ListSelectorEntriesResponse{
		RegisteredEntryList: s.listMatchingEntries(request.Selectors),
	}, nil
}

func (s *FakeDataStore) ListMatchingEntries(ctx context.Context,
	request *datastore.ListSelectorEntriesRequest) (*datastore.ListSelectorEntriesResponse, error) {

	s.mu.Lock()
	defer s.mu.Unlock()

	resp := &datastore.ListSelectorEntriesResponse{}
	for combination := range selector.NewSetFromRaw(request.Selectors).Power() {
		entries := s.listMatchingEntries(combination.Raw())
		resp.RegisteredEntryList = append(resp.RegisteredEntryList, entries...)
	}

	return resp, nil
}

func (s *FakeDataStore) listMatchingEntries(selectors []*common.Selector) (
	matches []*common.RegistrationEntry) {

	if len(selectors) == 0 {
		return nil
	}

	for _, registrationEntry := range s.registrationEntries {
		if !containsSelectors(registrationEntry.Selectors, selectors) {
			continue
		}
		if len(registrationEntry.Selectors) != len(selectors) {
			continue
		}

		matches = append(matches, cloneRegistrationEntry(registrationEntry))
	}

	return matches
}

func (s *FakeDataStore) ListSpiffeEntries(ctx context.Context,
	request *datastore.ListSpiffeEntriesRequest) (*datastore.ListSpiffeEntriesResponse, error) {

	s.mu.Lock()
	defer s.mu.Unlock()

	var registeredEntryList []*common.RegistrationEntry
	for _, registrationEntry := range s.registrationEntries {
		if registrationEntry.SpiffeId == request.SpiffeId {
			registeredEntryList = append(registeredEntryList, cloneRegistrationEntry(registrationEntry))
		}
	}

	return &datastore.ListSpiffeEntriesResponse{
		RegisteredEntryList: registeredEntryList,
	}, nil
}

// RegisterToken takes a Token message and stores it
func (s *FakeDataStore) RegisterToken(ctx context.Context, req *datastore.JoinToken) (*common.Empty, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.tokens[req.Token]; ok {
		return nil, ErrTokenAlreadyExists
	}
	s.tokens[req.Token] = cloneJoinToken(req)

	return &common.Empty{}, nil
}

// FetchToken takes a Token message and returns one, populating the fields
// we have knowledge of
func (s *FakeDataStore) FetchToken(ctx context.Context, req *datastore.JoinToken) (*datastore.JoinToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	token, ok := s.tokens[req.Token]
	if !ok {
		return &datastore.JoinToken{}, nil
	}

	return cloneJoinToken(token), nil
}

func (s *FakeDataStore) DeleteToken(ctx context.Context, req *datastore.JoinToken) (*common.Empty, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, ok := s.tokens[req.Token]
	if !ok {
		return nil, ErrNoSuchToken
	}
	delete(s.tokens, req.Token)

	return &common.Empty{}, nil
}

// PruneTokens takes a Token message, and deletes all tokens which have expired
// before the date in the message
func (s *FakeDataStore) PruneTokens(ctx context.Context, req *datastore.JoinToken) (*common.Empty, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for key, token := range s.tokens {
		if token.Expiry <= req.Expiry {
			delete(s.tokens, key)
		}
	}

	return &common.Empty{}, nil
}

func (s *FakeDataStore) Configure(ctx context.Context, req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	return &spi.ConfigureResponse{}, nil
}

func (FakeDataStore) GetPluginInfo(context.Context, *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &spi.GetPluginInfoResponse{}, nil
}

func cloneBundle(bundle *datastore.Bundle) *datastore.Bundle {
	return proto.Clone(bundle).(*datastore.Bundle)
}

func cloneAttestedNodeEntry(attestedNodeEntry *datastore.AttestedNodeEntry) *datastore.AttestedNodeEntry {
	return proto.Clone(attestedNodeEntry).(*datastore.AttestedNodeEntry)
}

func cloneNodeResolverMapEntry(nodeResolverMapEntry *datastore.NodeResolverMapEntry) *datastore.NodeResolverMapEntry {
	return proto.Clone(nodeResolverMapEntry).(*datastore.NodeResolverMapEntry)
}

func cloneRegistrationEntry(registrationEntry *datastore.RegistrationEntry) *datastore.RegistrationEntry {
	return proto.Clone(registrationEntry).(*datastore.RegistrationEntry)
}

func cloneJoinToken(token *datastore.JoinToken) *datastore.JoinToken {
	return proto.Clone(token).(*datastore.JoinToken)
}

func nodeResolverMapEntryKey(nodeResolverMapEntry *datastore.NodeResolverMapEntry) string {
	return fmt.Sprintf("%s%c%s%c%s",
		nodeResolverMapEntry.BaseSpiffeId, selectorKeySeparator,
		nodeResolverMapEntry.Selector.Type, selectorKeySeparator,
		nodeResolverMapEntry.Selector.Value)
}

func nodeResolverMapEntrySpiffeIDPrefix(spiffeID string) string {
	return fmt.Sprintf("%s%c", spiffeID, selectorKeySeparator)
}

func newRegistrationEntryID() (string, error) {
	entryID, err := uuid.NewV4()
	if err != nil {
		return "", fmt.Errorf("could not generate entry id: %v", err)
	}
	return entryID.String(), nil
}

func containsSelectors(selectors, subset []*common.Selector) bool {
nextSelector:
	for _, candidate := range subset {
		for _, selector := range selectors {
			if candidate.Type == selector.Type && candidate.Value == selector.Value {
				break nextSelector
			}
		}
		return false
	}
	return true
}
