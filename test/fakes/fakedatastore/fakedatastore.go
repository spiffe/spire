package fakedatastore

import (
	"context"
	"fmt"
	"sort"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/require"

	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/pkg/server/plugin/datastore"
	"github.com/spiffe/spire/pkg/server/plugin/datastore/sql"
	"github.com/spiffe/spire/proto/spire/common"
)

var (
	nextID uint32
)

type DataStore struct {
	ds   datastore.DataStore
	errs []error
}

var _ datastore.DataStore = (*DataStore)(nil)

func New(tb testing.TB) *DataStore {
	log, _ := test.NewNullLogger()

	ds := sql.New(log)

	err := ds.Configure(fmt.Sprintf(`
		database_type = "sqlite3"
		connection_string = "file:memdb%d?mode=memory&cache=shared"
	`, atomic.AddUint32(&nextID, 1)))
	require.NoError(tb, err)

	return &DataStore{
		ds: ds,
	}
}

func (s *DataStore) CreateBundle(ctx context.Context, bundle *common.Bundle) (*common.Bundle, error) {
	if err := s.getNextError(); err != nil {
		return nil, err
	}
	return s.ds.CreateBundle(ctx, bundle)
}

func (s *DataStore) UpdateBundle(ctx context.Context, bundle *common.Bundle, mask *common.BundleMask) (*common.Bundle, error) {
	if err := s.getNextError(); err != nil {
		return nil, err
	}
	return s.ds.UpdateBundle(ctx, bundle, mask)
}

func (s *DataStore) SetBundle(ctx context.Context, bundle *common.Bundle) (*common.Bundle, error) {
	if err := s.getNextError(); err != nil {
		return nil, err
	}
	return s.ds.SetBundle(ctx, bundle)
}

func (s *DataStore) AppendBundle(ctx context.Context, bundle *common.Bundle) (*common.Bundle, error) {
	if err := s.getNextError(); err != nil {
		return nil, err
	}
	return s.ds.AppendBundle(ctx, bundle)
}

func (s *DataStore) CountBundles(ctx context.Context) (int32, error) {
	if err := s.getNextError(); err != nil {
		return 0, err
	}

	return s.ds.CountBundles(ctx)
}

func (s *DataStore) DeleteBundle(ctx context.Context, trustDomain string, mode datastore.DeleteMode) error {
	if err := s.getNextError(); err != nil {
		return err
	}
	return s.ds.DeleteBundle(ctx, trustDomain, mode)
}

func (s *DataStore) FetchBundle(ctx context.Context, trustDomain string) (*common.Bundle, error) {
	if err := s.getNextError(); err != nil {
		return nil, err
	}
	return s.ds.FetchBundle(ctx, trustDomain)
}

func (s *DataStore) ListBundles(ctx context.Context, req *datastore.ListBundlesRequest) (*datastore.ListBundlesResponse, error) {
	if err := s.getNextError(); err != nil {
		return nil, err
	}
	resp, err := s.ds.ListBundles(ctx, req)
	if err == nil {
		// Sorting helps unit-tests have deterministic assertions.
		sort.Slice(resp.Bundles, func(i, j int) bool {
			return resp.Bundles[i].TrustDomainId < resp.Bundles[j].TrustDomainId
		})
	}
	return resp, err
}

func (s *DataStore) PruneBundle(ctx context.Context, trustDomainID string, expiresBefore time.Time) (bool, error) {
	if err := s.getNextError(); err != nil {
		return false, err
	}
	return s.ds.PruneBundle(ctx, trustDomainID, expiresBefore)
}

func (s *DataStore) CountAttestedNodes(ctx context.Context) (int32, error) {
	if err := s.getNextError(); err != nil {
		return 0, err
	}
	return s.ds.CountAttestedNodes(ctx)
}

func (s *DataStore) CreateAttestedNode(ctx context.Context, node *common.AttestedNode) (*common.AttestedNode, error) {
	if err := s.getNextError(); err != nil {
		return nil, err
	}
	return s.ds.CreateAttestedNode(ctx, node)
}

func (s *DataStore) FetchAttestedNode(ctx context.Context, spiffeID string) (*common.AttestedNode, error) {
	if err := s.getNextError(); err != nil {
		return nil, err
	}
	return s.ds.FetchAttestedNode(ctx, spiffeID)
}

func (s *DataStore) ListAttestedNodes(ctx context.Context, req *datastore.ListAttestedNodesRequest) (*datastore.ListAttestedNodesResponse, error) {
	if err := s.getNextError(); err != nil {
		return nil, err
	}
	return s.ds.ListAttestedNodes(ctx, req)
}

func (s *DataStore) UpdateAttestedNode(ctx context.Context, node *common.AttestedNode, mask *common.AttestedNodeMask) (*common.AttestedNode, error) {
	if err := s.getNextError(); err != nil {
		return nil, err
	}
	return s.ds.UpdateAttestedNode(ctx, node, mask)
}

func (s *DataStore) DeleteAttestedNode(ctx context.Context, spiffeID string) (*common.AttestedNode, error) {
	if err := s.getNextError(); err != nil {
		return nil, err
	}
	return s.ds.DeleteAttestedNode(ctx, spiffeID)
}

func (s *DataStore) SetNodeSelectors(ctx context.Context, spiffeID string, selectors []*common.Selector) error {
	if err := s.getNextError(); err != nil {
		return err
	}
	return s.ds.SetNodeSelectors(ctx, spiffeID, selectors)
}

func (s *DataStore) ListNodeSelectors(ctx context.Context, req *datastore.ListNodeSelectorsRequest) (*datastore.ListNodeSelectorsResponse, error) {
	if err := s.getNextError(); err != nil {
		return nil, err
	}
	return s.ds.ListNodeSelectors(ctx, req)
}

func (s *DataStore) GetNodeSelectors(ctx context.Context, spiffeID string, dbPreference datastore.DataConsistency) ([]*common.Selector, error) {
	if err := s.getNextError(); err != nil {
		return nil, err
	}
	selectors, err := s.ds.GetNodeSelectors(ctx, spiffeID, dbPreference)
	if err == nil {
		// Sorting helps unit-tests have deterministic assertions.
		util.SortSelectors(selectors)
	}
	return selectors, err
}

func (s *DataStore) CountRegistrationEntries(ctx context.Context) (int32, error) {
	if err := s.getNextError(); err != nil {
		return 0, err
	}
	return s.ds.CountRegistrationEntries(ctx)
}

func (s *DataStore) CreateRegistrationEntry(ctx context.Context, entry *common.RegistrationEntry) (*common.RegistrationEntry, error) {
	if err := s.getNextError(); err != nil {
		return nil, err
	}
	return s.ds.CreateRegistrationEntry(ctx, entry)
}

func (s *DataStore) FetchRegistrationEntry(ctx context.Context, entryID string) (*common.RegistrationEntry, error) {
	if err := s.getNextError(); err != nil {
		return nil, err
	}
	return s.ds.FetchRegistrationEntry(ctx, entryID)
}

func (s *DataStore) ListRegistrationEntries(ctx context.Context, req *datastore.ListRegistrationEntriesRequest) (*datastore.ListRegistrationEntriesResponse, error) {
	if err := s.getNextError(); err != nil {
		return nil, err
	}
	resp, err := s.ds.ListRegistrationEntries(ctx, req)
	if err == nil {
		// Sorting helps unit-tests have deterministic assertions.
		util.SortRegistrationEntries(resp.Entries)
	}
	return resp, err
}

func (s *DataStore) UpdateRegistrationEntry(ctx context.Context, entry *common.RegistrationEntry, mask *common.RegistrationEntryMask) (*common.RegistrationEntry, error) {
	if err := s.getNextError(); err != nil {
		return nil, err
	}
	return s.ds.UpdateRegistrationEntry(ctx, entry, mask)
}

func (s *DataStore) DeleteRegistrationEntry(ctx context.Context, entryID string) (*common.RegistrationEntry, error) {
	if err := s.getNextError(); err != nil {
		return nil, err
	}
	return s.ds.DeleteRegistrationEntry(ctx, entryID)
}

func (s *DataStore) PruneRegistrationEntries(ctx context.Context, expiresBefore time.Time) error {
	if err := s.getNextError(); err != nil {
		return err
	}
	return s.ds.PruneRegistrationEntries(ctx, expiresBefore)
}

func (s *DataStore) CreateJoinToken(ctx context.Context, token *datastore.JoinToken) error {
	if err := s.getNextError(); err != nil {
		return err
	}
	return s.ds.CreateJoinToken(ctx, token)
}

func (s *DataStore) FetchJoinToken(ctx context.Context, token string) (*datastore.JoinToken, error) {
	if err := s.getNextError(); err != nil {
		return nil, err
	}
	return s.ds.FetchJoinToken(ctx, token)
}

func (s *DataStore) DeleteJoinToken(ctx context.Context, token string) error {
	if err := s.getNextError(); err != nil {
		return err
	}
	return s.ds.DeleteJoinToken(ctx, token)
}

func (s *DataStore) PruneJoinTokens(ctx context.Context, expiresBefore time.Time) error {
	if err := s.getNextError(); err != nil {
		return err
	}
	return s.ds.PruneJoinTokens(ctx, expiresBefore)
}

func (s *DataStore) SetNextError(err error) {
	s.errs = []error{err}
}

func (s *DataStore) AppendNextError(err error) {
	s.errs = append(s.errs, err)
}

func (s *DataStore) getNextError() error {
	if len(s.errs) == 0 {
		return nil
	}
	err := s.errs[0]
	s.errs = s.errs[1:]
	return err
}
