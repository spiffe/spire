package fakedatastore

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"sync"

	radix "github.com/armon/go-radix"
	"github.com/golang/protobuf/proto"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
	uuid "github.com/satori/go.uuid"
	"github.com/spiffe/spire/pkg/common/selector"
	"github.com/spiffe/spire/pkg/common/util"
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

type DataStore struct {
	mu sync.Mutex

	bundles                map[string]*datastore.Bundle
	attestedNodeEntries    map[string]*datastore.AttestedNodeEntry
	nodeResolverMapEntries *radix.Tree
	registrationEntries    map[string]*datastore.RegistrationEntry
	tokens                 map[string]*datastore.JoinToken
}

var _ datastore.DataStore = (*DataStore)(nil)

func New() *DataStore {
	return &DataStore{
		bundles:                make(map[string]*datastore.Bundle),
		attestedNodeEntries:    make(map[string]*datastore.AttestedNodeEntry),
		nodeResolverMapEntries: radix.New(),
		registrationEntries:    make(map[string]*datastore.RegistrationEntry),
		tokens:                 make(map[string]*datastore.JoinToken),
	}
}

// CreateBundle stores the given bundle
func (s *DataStore) CreateBundle(ctx context.Context, req *datastore.CreateBundleRequest) (*datastore.CreateBundleResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	bundle := req.Bundle

	if _, ok := s.bundles[bundle.TrustDomain]; ok {
		return nil, ErrBundleAlreadyExists
	}

	s.bundles[bundle.TrustDomain] = cloneBundle(bundle)
	return &datastore.CreateBundleResponse{
		Bundle: cloneBundle(bundle),
	}, nil
}

// UpdateBundle updates an existing bundle with the given CAs. Overwrites any
// existing certificates.
func (s *DataStore) UpdateBundle(ctx context.Context, req *datastore.UpdateBundleRequest) (*datastore.UpdateBundleResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	bundle := req.Bundle

	s.bundles[bundle.TrustDomain] = cloneBundle(bundle)
	return &datastore.UpdateBundleResponse{
		Bundle: cloneBundle(bundle),
	}, nil
}

// AppendBundle adds the specified CA certificates to an existing bundle. If no bundle exists for the
// specified trust domain, create one. Returns the entirety.
func (s *DataStore) AppendBundle(ctx context.Context, req *datastore.AppendBundleRequest) (*datastore.AppendBundleResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	bundleIn := req.Bundle

	reqCerts, err := x509.ParseCertificates(bundleIn.CaCerts)
	if err != nil {
		return nil, err
	}

	bundle, ok := s.bundles[bundleIn.TrustDomain]
	if !ok {
		bundle = &datastore.Bundle{
			TrustDomain: bundleIn.TrustDomain,
		}
		s.bundles[bundle.TrustDomain] = bundle
	}

	bundleCerts, err := x509.ParseCertificates(bundle.CaCerts)
	if err != nil {
		return nil, err
	}

	// datastore has a job to dedup cacerts being appended to the bundle
	for _, reqCert := range reqCerts {
		found := false
		for _, bundleCert := range bundleCerts {
			if bytes.Equal(reqCert.Raw, bundleCert.Raw) {
				found = true
				break
			}
		}
		if !found {
			bundle.CaCerts = append(bundle.CaCerts, cloneBytes(reqCert.Raw)...)
		}
	}

	return &datastore.AppendBundleResponse{
		Bundle: cloneBundle(bundle),
	}, nil
}

// DeleteBundle deletes the bundle with the matching TrustDomain. Any CACert data passed is ignored.
func (s *DataStore) DeleteBundle(ctx context.Context, req *datastore.DeleteBundleRequest) (*datastore.DeleteBundleResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	bundle, ok := s.bundles[req.TrustDomain]
	if !ok {
		return nil, ErrNoSuchBundle
	}
	delete(s.bundles, req.TrustDomain)

	return &datastore.DeleteBundleResponse{
		Bundle: cloneBundle(bundle),
	}, nil
}

// FetchBundle returns the bundle matching the specified Trust Domain.
func (s *DataStore) FetchBundle(ctx context.Context, req *datastore.FetchBundleRequest) (*datastore.FetchBundleResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	bundle, ok := s.bundles[req.TrustDomain]
	if !ok {
		return nil, ErrNoSuchBundle
	}

	return &datastore.FetchBundleResponse{
		Bundle: cloneBundle(bundle),
	}, nil
}

// ListBundles can be used to fetch all existing bundles.
func (s *DataStore) ListBundles(ctx context.Context, req *datastore.ListBundlesRequest) (*datastore.ListBundlesResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	resp := new(datastore.ListBundlesResponse)
	for _, bundle := range s.bundles {
		resp.Bundles = append(resp.Bundles, cloneBundle(bundle))
	}

	return resp, nil
}

func (s *DataStore) CreateAttestedNodeEntry(ctx context.Context,
	req *datastore.CreateAttestedNodeEntryRequest) (*datastore.CreateAttestedNodeEntryResponse, error) {

	s.mu.Lock()
	defer s.mu.Unlock()

	entry := req.Entry

	if _, ok := s.attestedNodeEntries[entry.SpiffeId]; ok {
		return nil, ErrAttestedNodeEntryAlreadyExists
	}

	s.attestedNodeEntries[entry.SpiffeId] = cloneAttestedNodeEntry(entry)
	return &datastore.CreateAttestedNodeEntryResponse{
		Entry: cloneAttestedNodeEntry(entry),
	}, nil
}

func (s *DataStore) FetchAttestedNodeEntry(ctx context.Context,
	req *datastore.FetchAttestedNodeEntryRequest) (*datastore.FetchAttestedNodeEntryResponse, error) {

	s.mu.Lock()
	defer s.mu.Unlock()

	resp := new(datastore.FetchAttestedNodeEntryResponse)
	bundle, ok := s.attestedNodeEntries[req.SpiffeId]
	if !ok {
		return resp, nil
	}
	resp.Entry = cloneAttestedNodeEntry(bundle)

	return resp, nil
}

func (s *DataStore) ListAttestedNodeEntries(ctx context.Context,
	req *datastore.ListAttestedNodeEntriesRequest) (*datastore.ListAttestedNodeEntriesResponse, error) {

	s.mu.Lock()
	defer s.mu.Unlock()

	resp := new(datastore.ListAttestedNodeEntriesResponse)
	for _, attestedNodeEntry := range s.attestedNodeEntries {
		if req.ByExpiresBefore != nil {
			if attestedNodeEntry.CertNotAfter >= req.ByExpiresBefore.Value {
				continue
			}
		}
		resp.Entries = append(resp.Entries, cloneAttestedNodeEntry(attestedNodeEntry))
	}

	return resp, nil
}

func (s *DataStore) UpdateAttestedNodeEntry(ctx context.Context,
	req *datastore.UpdateAttestedNodeEntryRequest) (*datastore.UpdateAttestedNodeEntryResponse, error) {

	s.mu.Lock()
	defer s.mu.Unlock()

	attestedNodeEntry, ok := s.attestedNodeEntries[req.SpiffeId]
	if !ok {
		return nil, ErrNoSuchAttestedNodeEntry
	}
	attestedNodeEntry.CertSerialNumber = req.CertSerialNumber
	attestedNodeEntry.CertNotAfter = req.CertNotAfter

	return &datastore.UpdateAttestedNodeEntryResponse{
		Entry: cloneAttestedNodeEntry(attestedNodeEntry),
	}, nil
}

func (s *DataStore) DeleteAttestedNodeEntry(ctx context.Context,
	req *datastore.DeleteAttestedNodeEntryRequest) (*datastore.DeleteAttestedNodeEntryResponse, error) {

	s.mu.Lock()
	defer s.mu.Unlock()

	attestedNodeEntry, ok := s.attestedNodeEntries[req.SpiffeId]
	if !ok {
		return nil, ErrNoSuchAttestedNodeEntry
	}
	delete(s.attestedNodeEntries, req.SpiffeId)

	return &datastore.DeleteAttestedNodeEntryResponse{
		Entry: cloneAttestedNodeEntry(attestedNodeEntry),
	}, nil
}

func (s *DataStore) CreateNodeResolverMapEntry(ctx context.Context,
	req *datastore.CreateNodeResolverMapEntryRequest) (*datastore.CreateNodeResolverMapEntryResponse, error) {

	s.mu.Lock()
	defer s.mu.Unlock()

	entry := req.Entry
	key := nodeResolverMapEntryKey(entry)

	if _, ok := s.nodeResolverMapEntries.Get(key); ok {
		return nil, ErrNodeResolverMapEntryAlreadyExists
	}

	s.nodeResolverMapEntries.Insert(key, cloneNodeResolverMapEntry(entry))
	return &datastore.CreateNodeResolverMapEntryResponse{
		Entry: cloneNodeResolverMapEntry(entry),
	}, nil
}

func (s *DataStore) ListNodeResolverMapEntries(ctx context.Context,
	req *datastore.ListNodeResolverMapEntriesRequest) (*datastore.ListNodeResolverMapEntriesResponse, error) {

	s.mu.Lock()
	defer s.mu.Unlock()

	s.nodeResolverMapEntries.Walk(func(key string, v interface{}) bool {
		return false
	})
	resp := new(datastore.ListNodeResolverMapEntriesResponse)
	s.nodeResolverMapEntries.WalkPrefix(
		nodeResolverMapEntrySpiffeIDPrefix(req.SpiffeId),
		func(key string, v interface{}) bool {
			resp.Entries = append(resp.Entries,
				cloneNodeResolverMapEntry(v.(*datastore.NodeResolverMapEntry)))
			return false
		})

	return resp, nil
}

func (s *DataStore) DeleteNodeResolverMapEntry(ctx context.Context,
	req *datastore.DeleteNodeResolverMapEntryRequest) (*datastore.DeleteNodeResolverMapEntryResponse, error) {

	s.mu.Lock()
	defer s.mu.Unlock()

	resp := new(datastore.DeleteNodeResolverMapEntryResponse)
	if req.Entry.Selector != nil {
		key := nodeResolverMapEntryKey(req.Entry)
		v, ok := s.nodeResolverMapEntries.Get(key)
		if !ok {
			return nil, ErrNoSuchNodeResolverMapEntry
		}
		resp.Entries = append(resp.Entries,
			cloneNodeResolverMapEntry(v.(*datastore.NodeResolverMapEntry)))
	} else {
		prefix := nodeResolverMapEntrySpiffeIDPrefix(req.Entry.SpiffeId)
		s.nodeResolverMapEntries.WalkPrefix(prefix,
			func(key string, v interface{}) bool {
				resp.Entries = append(resp.Entries,
					cloneNodeResolverMapEntry(v.(*datastore.NodeResolverMapEntry)))
				return true
			})
		s.nodeResolverMapEntries.DeletePrefix(prefix)
	}

	return resp, nil
}

func (DataStore) RectifyNodeResolverMapEntries(ctx context.Context,
	req *datastore.RectifyNodeResolverMapEntriesRequest) (*datastore.RectifyNodeResolverMapEntriesResponse, error) {
	return &datastore.RectifyNodeResolverMapEntriesResponse{}, errors.New("Not Implemented")
}

func (s *DataStore) CreateRegistrationEntry(ctx context.Context,
	req *datastore.CreateRegistrationEntryRequest) (*datastore.CreateRegistrationEntryResponse, error) {

	s.mu.Lock()
	defer s.mu.Unlock()

	entryID, err := newRegistrationEntryID()
	if err != nil {
		return nil, err
	}

	entry := cloneRegistrationEntry(req.Entry)
	entry.EntryId = entryID
	s.registrationEntries[entryID] = entry

	return &datastore.CreateRegistrationEntryResponse{
		EntryId: entryID,
	}, nil
}

func (s *DataStore) FetchRegistrationEntry(ctx context.Context,
	req *datastore.FetchRegistrationEntryRequest) (*datastore.FetchRegistrationEntryResponse, error) {

	s.mu.Lock()
	defer s.mu.Unlock()

	resp := new(datastore.FetchRegistrationEntryResponse)
	entry, ok := s.registrationEntries[req.EntryId]
	if !ok {
		return resp, nil
	}
	resp.Entry = cloneRegistrationEntry(entry)

	return resp, nil
}

func (s *DataStore) ListRegistrationEntries(ctx context.Context,
	req *datastore.ListRegistrationEntriesRequest) (*datastore.ListRegistrationEntriesResponse, error) {

	s.mu.Lock()
	defer s.mu.Unlock()

	// add the registration entries to the map
	entriesSet := make(map[string]*common.RegistrationEntry)
	for _, entry := range s.registrationEntries {
		if req.ByParentId != nil && entry.ParentId != req.ByParentId.Value {
			continue
		}
		if req.BySpiffeId != nil && entry.SpiffeId != req.BySpiffeId.Value {
			continue
		}

		entriesSet[entry.EntryId] = entry
	}

	if req.BySelectors != nil && len(req.BySelectors.Selectors) > 0 {
		var selectorsList [][]*common.Selector
		selectorSet := selector.NewSetFromRaw(req.BySelectors.Selectors)
		if req.BySelectors.AllowAnyCombination {
			for combination := range selectorSet.Power() {
				selectorsList = append(selectorsList, combination.Raw())
			}
		} else {
			selectorsList = append(selectorsList, selectorSet.Raw())
		}

		// filter entries that don't match at least one selector set
		for entryID, entry := range entriesSet {
			matchesOne := false
			for _, selectors := range selectorsList {
				if !containsSelectors(entry.Selectors, selectors) {
					continue
				}
				if len(entry.Selectors) != len(selectors) {
					continue
				}
				matchesOne = true
				break
			}
			if !matchesOne {
				delete(entriesSet, entryID)
			}
		}
	}

	// clone and sort entries from the set
	entries := make([]*common.RegistrationEntry, 0, len(entriesSet))
	for _, entry := range entriesSet {
		entries = append(entries, cloneRegistrationEntry(entry))
	}
	util.SortRegistrationEntries(entries)

	return &datastore.ListRegistrationEntriesResponse{
		Entries: entries,
	}, nil
}

func (s DataStore) UpdateRegistrationEntry(ctx context.Context,
	req *datastore.UpdateRegistrationEntryRequest) (*datastore.UpdateRegistrationEntryResponse, error) {

	s.mu.Lock()
	defer s.mu.Unlock()

	_, ok := s.registrationEntries[req.Entry.EntryId]
	if !ok {
		return nil, ErrNoSuchRegistrationEntry
	}

	entry := cloneRegistrationEntry(req.Entry)
	s.registrationEntries[req.Entry.EntryId] = entry

	return &datastore.UpdateRegistrationEntryResponse{
		Entry: cloneRegistrationEntry(entry),
	}, nil
}

func (s *DataStore) DeleteRegistrationEntry(ctx context.Context,
	req *datastore.DeleteRegistrationEntryRequest) (*datastore.DeleteRegistrationEntryResponse, error) {

	s.mu.Lock()
	defer s.mu.Unlock()

	registrationEntry, ok := s.registrationEntries[req.EntryId]
	if !ok {
		return nil, ErrNoSuchRegistrationEntry
	}
	delete(s.registrationEntries, req.EntryId)

	return &datastore.DeleteRegistrationEntryResponse{
		Entry: cloneRegistrationEntry(registrationEntry),
	}, nil
}

// CreateJoinToken takes a Token message and stores it
func (s *DataStore) CreateJoinToken(ctx context.Context, req *datastore.CreateJoinTokenRequest) (*datastore.CreateJoinTokenResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.tokens[req.JoinToken.Token]; ok {
		return nil, ErrTokenAlreadyExists
	}
	s.tokens[req.JoinToken.Token] = cloneJoinToken(req.JoinToken)

	return &datastore.CreateJoinTokenResponse{
		JoinToken: cloneJoinToken(req.JoinToken),
	}, nil
}

// FetchToken takes a Token message and returns one, populating the fields
// we have knowledge of
func (s *DataStore) FetchJoinToken(ctx context.Context, req *datastore.FetchJoinTokenRequest) (*datastore.FetchJoinTokenResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	joinToken, ok := s.tokens[req.Token]
	if !ok {
		return &datastore.FetchJoinTokenResponse{}, nil
	}

	return &datastore.FetchJoinTokenResponse{
		JoinToken: cloneJoinToken(joinToken),
	}, nil
}

func (s *DataStore) DeleteJoinToken(ctx context.Context, req *datastore.DeleteJoinTokenRequest) (*datastore.DeleteJoinTokenResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	joinToken, ok := s.tokens[req.Token]
	if !ok {
		return nil, ErrNoSuchToken
	}
	delete(s.tokens, req.Token)

	return &datastore.DeleteJoinTokenResponse{
		JoinToken: cloneJoinToken(joinToken),
	}, nil
}

func (s *DataStore) PruneJoinTokens(ctx context.Context, req *datastore.PruneJoinTokensRequest) (*datastore.PruneJoinTokensResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for key, token := range s.tokens {
		if token.Expiry <= req.ExpiresBefore {
			delete(s.tokens, key)
		}
	}

	return &datastore.PruneJoinTokensResponse{}, nil
}

func (s *DataStore) Configure(ctx context.Context, req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	return &spi.ConfigureResponse{}, nil
}

func (DataStore) GetPluginInfo(context.Context, *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &spi.GetPluginInfoResponse{}, nil
}

func cloneBytes(bytes []byte) []byte {
	return append([]byte(nil), bytes...)
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
		nodeResolverMapEntry.SpiffeId, selectorKeySeparator,
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
