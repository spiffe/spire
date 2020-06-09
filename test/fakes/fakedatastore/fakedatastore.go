package fakedatastore

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/hashicorp/go-hclog"

	"github.com/gofrs/uuid"
	"github.com/golang/protobuf/proto"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/common/selector"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/pkg/server/plugin/datastore"
	"github.com/spiffe/spire/proto/spire/common"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	// TODO: The following errors should be grpc/status errors with the AlreadyExists code. #992

	ErrBundleAlreadyExists       = errors.New("bundle already exists")
	ErrAttestedNodeAlreadyExists = errors.New("attested node entry already exists")
	ErrTokenAlreadyExists        = errors.New("token already exists")

	ErrNoSuchBundle            = status.Error(codes.NotFound, "no such bundle")
	ErrNoSuchAttestedNode      = status.Error(codes.NotFound, "no such attested node entry")
	ErrNoSuchRegistrationEntry = status.Error(codes.NotFound, "no such registration entry")
	ErrNoSuchToken             = status.Error(codes.NotFound, "no such token")
)

type DataStore struct {
	mu sync.Mutex

	bundles             map[string]*common.Bundle
	attestedNodes       map[string]*common.AttestedNode
	nodeSelectors       map[string][]*common.Selector
	registrationEntries map[string]*common.RegistrationEntry
	tokens              map[string]*datastore.JoinToken

	// relates bundles with entries that federate with them
	bundleEntries map[string]map[string]bool

	// expect error when calling functions
	expectErr error
}

var _ datastore.DataStore = (*DataStore)(nil)

func New() *DataStore {
	return &DataStore{
		bundles:             make(map[string]*common.Bundle),
		attestedNodes:       make(map[string]*common.AttestedNode),
		nodeSelectors:       make(map[string][]*common.Selector),
		registrationEntries: make(map[string]*common.RegistrationEntry),
		tokens:              make(map[string]*datastore.JoinToken),
		bundleEntries:       make(map[string]map[string]bool),
	}
}

// CreateBundle stores the given bundle
func (s *DataStore) CreateBundle(ctx context.Context, req *datastore.CreateBundleRequest) (*datastore.CreateBundleResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	bundle := req.Bundle

	if _, ok := s.bundles[bundle.TrustDomainId]; ok {
		return nil, ErrBundleAlreadyExists
	}

	s.bundles[bundle.TrustDomainId] = cloneBundle(bundle)

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

	if _, ok := s.bundles[bundle.TrustDomainId]; !ok {
		return nil, ErrNoSuchBundle
	}

	s.bundles[bundle.TrustDomainId] = cloneBundle(bundle)

	return &datastore.UpdateBundleResponse{
		Bundle: cloneBundle(bundle),
	}, nil
}

// SetBundle sets bundle contents. If no bundle exists for the trust domain, it is created.
func (s *DataStore) SetBundle(ctx context.Context, req *datastore.SetBundleRequest) (*datastore.SetBundleResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	bundle := req.Bundle

	s.bundles[bundle.TrustDomainId] = cloneBundle(bundle)

	return &datastore.SetBundleResponse{
		Bundle: cloneBundle(bundle),
	}, nil
}

// AppendBundle updates an existing bundle with the given CAs. Overwrites any
// existing certificates.
func (s *DataStore) AppendBundle(ctx context.Context, req *datastore.AppendBundleRequest) (*datastore.AppendBundleResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.expectErr != nil {
		return nil, s.expectErr
	}

	bundle := req.Bundle

	if existingBundle, ok := s.bundles[bundle.TrustDomainId]; ok {
		bundle, _ = bundleutil.MergeBundles(existingBundle, bundle)
	}

	s.bundles[bundle.TrustDomainId] = cloneBundle(bundle)

	return &datastore.AppendBundleResponse{
		Bundle: cloneBundle(bundle),
	}, nil
}

// DeleteBundle deletes the bundle with the matching TrustDomainId. Any CACert data passed is ignored.
func (s *DataStore) DeleteBundle(ctx context.Context, req *datastore.DeleteBundleRequest) (*datastore.DeleteBundleResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.expectErr != nil {
		return nil, s.expectErr
	}

	bundle, ok := s.bundles[req.TrustDomainId]
	if !ok {
		return nil, ErrNoSuchBundle
	}

	if bundleEntries := s.bundleEntries[req.TrustDomainId]; len(bundleEntries) > 0 {
		switch req.Mode {
		case datastore.DeleteBundleRequest_DELETE:
			for entryID := range bundleEntries {
				delete(s.registrationEntries, entryID)
			}
		case datastore.DeleteBundleRequest_DISSOCIATE:
			for entryID := range bundleEntries {
				if entry := s.registrationEntries[entryID]; entry != nil {
					entry.FederatesWith = removeString(entry.FederatesWith, req.TrustDomainId)
				}
			}
		default:
			return nil, fmt.Errorf("cannot delete bundle; federated with %d registration entries", len(bundleEntries))
		}
	}
	delete(s.bundles, req.TrustDomainId)

	return &datastore.DeleteBundleResponse{
		Bundle: cloneBundle(bundle),
	}, nil
}

// FetchBundle returns the bundle matching the specified Trust Domain.
func (s *DataStore) FetchBundle(ctx context.Context, req *datastore.FetchBundleRequest) (*datastore.FetchBundleResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.expectErr != nil {
		return nil, s.expectErr
	}

	bundle, ok := s.bundles[req.TrustDomainId]
	if !ok {
		return &datastore.FetchBundleResponse{}, nil
	}

	return &datastore.FetchBundleResponse{
		Bundle: cloneBundle(bundle),
	}, nil
}

// ListBundles can be used to fetch all existing bundles.
func (s *DataStore) ListBundles(ctx context.Context, req *datastore.ListBundlesRequest) (*datastore.ListBundlesResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// get an ordered list of keys so tests can rely on ordering for stability
	keys := make([]string, 0, len(s.bundles))
	for key := range s.bundles {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	resp := new(datastore.ListBundlesResponse)

	p := req.Pagination
	// in case pagination is defined and page size greater than zero apply pagination
	if p != nil && p.PageSize > 0 {
		// as default start in first position
		init := 0

		// If token is defined set index of initial element
		if p.Token != "" {
			init = sort.StringSlice(keys).Search(p.Token) + 1
		}

		// set end as initial element + page size, if end is greater to entries size use length as end
		length := len(keys)
		end := init + int(p.PageSize)
		if end > length {
			end = length
		}

		// create a new array with paged bundles
		keys = keys[init:end]
		if len(keys) > 0 {
			lastIndex := len(keys) - 1
			// change token to latests bundle key
			resp.Pagination = &datastore.Pagination{
				PageSize: p.PageSize,
				Token:    keys[lastIndex],
			}
		}
	}

	for _, key := range keys {
		resp.Bundles = append(resp.Bundles, cloneBundle(s.bundles[key]))
	}

	return resp, nil
}

// PruneBundle removes expired certs from a bundle
func (s *DataStore) PruneBundle(ctx context.Context, req *datastore.PruneBundleRequest) (*datastore.PruneBundleResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	oldBundle, ok := s.bundles[req.TrustDomainId]
	if !ok {
		// No bundle to prune
		return &datastore.PruneBundleResponse{}, nil
	}

	newBundle, changed, err := bundleutil.PruneBundle(oldBundle, time.Unix(req.ExpiresBefore, 0), hclog.NewNullLogger())
	if err != nil {
		return nil, fmt.Errorf("prune failed: %v", err)
	}

	// If any cert was pruned, then update the bundle
	if changed {
		s.bundles[req.TrustDomainId] = newBundle
	}

	return &datastore.PruneBundleResponse{BundleChanged: changed}, nil
}

func (s *DataStore) CreateAttestedNode(ctx context.Context, req *datastore.CreateAttestedNodeRequest) (*datastore.CreateAttestedNodeResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	node := req.Node

	if _, ok := s.attestedNodes[node.SpiffeId]; ok {
		return nil, ErrAttestedNodeAlreadyExists
	}

	s.attestedNodes[node.SpiffeId] = cloneAttestedNode(node)
	return &datastore.CreateAttestedNodeResponse{
		Node: cloneAttestedNode(node),
	}, nil
}

func (s *DataStore) FetchAttestedNode(ctx context.Context, req *datastore.FetchAttestedNodeRequest) (*datastore.FetchAttestedNodeResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	resp := new(datastore.FetchAttestedNodeResponse)
	node, ok := s.attestedNodes[req.SpiffeId]
	if !ok {
		return resp, nil
	}
	resp.Node = cloneAttestedNode(node)

	return resp, nil
}

func (s *DataStore) ListAttestedNodes(ctx context.Context, req *datastore.ListAttestedNodesRequest) (*datastore.ListAttestedNodesResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// get an ordered list of keys so tests can rely on ordering for stability
	keys := make([]string, 0, len(s.attestedNodes))
	for key := range s.attestedNodes {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	resp := new(datastore.ListAttestedNodesResponse)
	for _, key := range keys {
		attestedNodeEntry := s.attestedNodes[key]
		if req.ByExpiresBefore != nil {
			if attestedNodeEntry.CertNotAfter >= req.ByExpiresBefore.Value {
				continue
			}
		}
		resp.Nodes = append(resp.Nodes, cloneAttestedNode(attestedNodeEntry))
	}

	return resp, nil
}

func (s *DataStore) UpdateAttestedNode(ctx context.Context, req *datastore.UpdateAttestedNodeRequest) (*datastore.UpdateAttestedNodeResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	node, ok := s.attestedNodes[req.SpiffeId]
	if !ok {
		return nil, ErrNoSuchAttestedNode
	}
	node.CertSerialNumber = req.CertSerialNumber
	node.CertNotAfter = req.CertNotAfter
	node.NewCertSerialNumber = req.NewCertSerialNumber
	node.NewCertNotAfter = req.NewCertNotAfter

	return &datastore.UpdateAttestedNodeResponse{
		Node: cloneAttestedNode(node),
	}, nil
}

func (s *DataStore) DeleteAttestedNode(ctx context.Context, req *datastore.DeleteAttestedNodeRequest) (*datastore.DeleteAttestedNodeResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	node, ok := s.attestedNodes[req.SpiffeId]
	if !ok {
		return nil, ErrNoSuchAttestedNode
	}
	delete(s.attestedNodes, req.SpiffeId)

	return &datastore.DeleteAttestedNodeResponse{
		Node: cloneAttestedNode(node),
	}, nil
}

func (s *DataStore) SetNodeSelectors(ctx context.Context, req *datastore.SetNodeSelectorsRequest) (*datastore.SetNodeSelectorsResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.nodeSelectors[req.Selectors.SpiffeId] = cloneSelectors(req.Selectors.Selectors)
	return &datastore.SetNodeSelectorsResponse{}, nil
}

func (s *DataStore) GetNodeSelectors(ctx context.Context, req *datastore.GetNodeSelectorsRequest) (*datastore.GetNodeSelectorsResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	selectors := s.nodeSelectors[req.SpiffeId]

	return &datastore.GetNodeSelectorsResponse{
		Selectors: &datastore.NodeSelectors{
			SpiffeId:  req.SpiffeId,
			Selectors: cloneSelectors(selectors),
		},
	}, nil
}

func (s *DataStore) CreateRegistrationEntry(ctx context.Context, req *datastore.CreateRegistrationEntryRequest) (*datastore.CreateRegistrationEntryResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entryID, err := newRegistrationEntryID()
	if err != nil {
		return nil, err
	}

	entry := cloneRegistrationEntry(req.Entry)
	entry.EntryId = entryID
	s.registrationEntries[entryID] = entry

	if err := s.addBundleLinks(entryID, req.Entry.FederatesWith); err != nil {
		return nil, err
	}

	return &datastore.CreateRegistrationEntryResponse{
		Entry: cloneRegistrationEntry(entry),
	}, nil
}

func (s *DataStore) FetchRegistrationEntry(ctx context.Context, req *datastore.FetchRegistrationEntryRequest) (*datastore.FetchRegistrationEntryResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.expectErr != nil {
		return nil, s.expectErr
	}

	resp := new(datastore.FetchRegistrationEntryResponse)
	entry, ok := s.registrationEntries[req.EntryId]
	if !ok {
		return resp, nil
	}
	resp.Entry = cloneRegistrationEntry(entry)

	return resp, nil
}

func (s *DataStore) ListRegistrationEntries(ctx context.Context, req *datastore.ListRegistrationEntriesRequest) (*datastore.ListRegistrationEntriesResponse, error) {
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
		switch req.BySelectors.Match {
		case datastore.BySelectors_MATCH_EXACT:
			selectorsList = append(selectorsList, selectorSet.Raw())
		case datastore.BySelectors_MATCH_SUBSET:
			for combination := range selectorSet.Power() {
				selectorsList = append(selectorsList, combination.Raw())
			}
		default:
			return nil, fmt.Errorf("unhandled match behavior %q", req.BySelectors.Match)
		}

		// filter entries that don't match at least one selector set
		for entryID, entry := range entriesSet {
			matchesOne := false
			for _, selectors := range selectorsList {
				if !matchesSelectors(entry.Selectors, selectors) {
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

	p := req.Pagination
	// in case pagination is defined and page size greater than zero apply pagination
	if p != nil && p.PageSize > 0 {
		// as default start in first position
		init := 0

		// If token is defined set index of initial element
		if p.Token != "" {
			init = indexOf(p.Token, entries) + 1
		}

		// set end as initial element + page size, if end is greater to entries size use length as end
		length := len(entries)
		end := init + int(p.PageSize)
		if end > length {
			end = length
		}

		// create a new array with paged entries
		pagedEntries := entries[init:end]
		var token string
		if len(pagedEntries) > 0 {
			lastIndex := len(pagedEntries) - 1
			// change token to latests element entryId
			token = pagedEntries[lastIndex].EntryId
		}
		return &datastore.ListRegistrationEntriesResponse{
			Entries: pagedEntries,
			Pagination: &datastore.Pagination{
				Token:    token,
				PageSize: p.PageSize,
			},
		}, nil
	}

	return &datastore.ListRegistrationEntriesResponse{
		Entries:    entries,
		Pagination: p,
	}, nil
}

func indexOf(element string, entries []*common.RegistrationEntry) int {
	for k, e := range entries {
		if element == e.EntryId {
			return k
		}
	}
	return -1
}

func (s *DataStore) UpdateRegistrationEntry(ctx context.Context, req *datastore.UpdateRegistrationEntryRequest) (*datastore.UpdateRegistrationEntryResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	oldEntry, ok := s.registrationEntries[req.Entry.EntryId]
	if !ok {
		return nil, ErrNoSuchRegistrationEntry
	}

	s.removeBundleLinks(oldEntry.EntryId, oldEntry.FederatesWith)

	entry := cloneRegistrationEntry(req.Entry)
	s.registrationEntries[req.Entry.EntryId] = entry

	if err := s.addBundleLinks(entry.EntryId, req.Entry.FederatesWith); err != nil {
		return nil, err
	}

	return &datastore.UpdateRegistrationEntryResponse{
		Entry: cloneRegistrationEntry(entry),
	}, nil
}

func (s *DataStore) DeleteRegistrationEntry(ctx context.Context, req *datastore.DeleteRegistrationEntryRequest) (*datastore.DeleteRegistrationEntryResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.expectErr != nil {
		return nil, s.expectErr
	}

	registrationEntry, ok := s.registrationEntries[req.EntryId]
	if !ok {
		return nil, ErrNoSuchRegistrationEntry
	}
	delete(s.registrationEntries, req.EntryId)

	s.removeBundleLinks(req.EntryId, registrationEntry.FederatesWith)

	return &datastore.DeleteRegistrationEntryResponse{
		Entry: cloneRegistrationEntry(registrationEntry),
	}, nil
}

func (s *DataStore) PruneRegistrationEntries(ctx context.Context, req *datastore.PruneRegistrationEntriesRequest) (*datastore.PruneRegistrationEntriesResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for key, entry := range s.registrationEntries {
		if entry.EntryExpiry != 0 && entry.EntryExpiry < req.ExpiresBefore {
			delete(s.registrationEntries, key)
		}
	}

	return &datastore.PruneRegistrationEntriesResponse{}, nil
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
		if token.Expiry < req.ExpiresBefore {
			delete(s.tokens, key)
		}
	}

	return &datastore.PruneJoinTokensResponse{}, nil
}

func (s *DataStore) SetError(err error) {
	s.expectErr = err
}

func (s *DataStore) Configure(ctx context.Context, req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	return &spi.ConfigureResponse{}, nil
}

func (*DataStore) GetPluginInfo(context.Context, *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &spi.GetPluginInfoResponse{}, nil
}

func (s *DataStore) addBundleLinks(entryID string, bundleIDs []string) error {
	for _, bundleID := range bundleIDs {
		if _, ok := s.bundles[bundleID]; !ok {
			return ErrNoSuchBundle
		}
		bundleEntries := s.bundleEntries[bundleID]
		if bundleEntries == nil {
			bundleEntries = make(map[string]bool)
			s.bundleEntries[bundleID] = bundleEntries
		}
		bundleEntries[entryID] = true
	}
	return nil
}

func (s *DataStore) removeBundleLinks(entryID string, bundleIDs []string) {
	for _, bundleID := range bundleIDs {
		delete(s.bundleEntries[bundleID], entryID)
	}
}

func cloneBundle(bundle *common.Bundle) *common.Bundle {
	return proto.Clone(bundle).(*common.Bundle)
}

func cloneAttestedNode(attestedNodeEntry *common.AttestedNode) *common.AttestedNode {
	return proto.Clone(attestedNodeEntry).(*common.AttestedNode)
}

func cloneSelectors(selectors []*common.Selector) []*common.Selector {
	return proto.Clone(&common.Selectors{Entries: selectors}).(*common.Selectors).Entries
}

func cloneRegistrationEntry(registrationEntry *common.RegistrationEntry) *common.RegistrationEntry {
	return proto.Clone(registrationEntry).(*common.RegistrationEntry)
}

func cloneJoinToken(token *datastore.JoinToken) *datastore.JoinToken {
	return proto.Clone(token).(*datastore.JoinToken)
}

func newRegistrationEntryID() (string, error) {
	u, err := uuid.NewV4()
	if err != nil {
		return "", err
	}
	return u.String(), nil
}

func matchesSelectors(a, b []*common.Selector) bool {
	a = append([]*common.Selector{}, a...)
	util.SortSelectors(a)
	b = append([]*common.Selector{}, b...)
	util.SortSelectors(b)
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		if !proto.Equal(a[i], b[i]) {
			return false
		}
	}
	return true
}

func removeString(list []string, s string) []string {
	out := make([]string, 0, len(list))
	for _, entry := range list {
		if entry != s {
			out = append(out, entry)
		}
	}
	return out
}
