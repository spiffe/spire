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

func (s *DataStore) UpdateBundle(ctx context.Context, req *datastore.UpdateBundleRequest) (*datastore.UpdateBundleResponse, error) {
	if err := s.getNextError(); err != nil {
		return nil, err
	}
	return s.ds.UpdateBundle(ctx, req)
}

func (s *DataStore) SetBundle(ctx context.Context, req *datastore.SetBundleRequest) (*datastore.SetBundleResponse, error) {
	if err := s.getNextError(); err != nil {
		return nil, err
	}
	return s.ds.SetBundle(ctx, req)
}

func (s *DataStore) AppendBundle(ctx context.Context, req *datastore.AppendBundleRequest) (*datastore.AppendBundleResponse, error) {
	if err := s.getNextError(); err != nil {
		return nil, err
	}
	return s.ds.AppendBundle(ctx, req)
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

func (s *DataStore) PruneBundle(ctx context.Context, req *datastore.PruneBundleRequest) (*datastore.PruneBundleResponse, error) {
	if err := s.getNextError(); err != nil {
		return nil, err
	}
	return s.ds.PruneBundle(ctx, req)
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

func (s *DataStore) UpdateAttestedNode(ctx context.Context, req *datastore.UpdateAttestedNodeRequest) (*datastore.UpdateAttestedNodeResponse, error) {
	if err := s.getNextError(); err != nil {
		return nil, err
	}
	return s.ds.UpdateAttestedNode(ctx, req)
}

func (s *DataStore) DeleteAttestedNode(ctx context.Context, spiffeID string) (*common.AttestedNode, error) {
	if err := s.getNextError(); err != nil {
		return nil, err
	}
	return s.ds.DeleteAttestedNode(ctx, spiffeID)
}

func (s *DataStore) SetNodeSelectors(ctx context.Context, req *datastore.SetNodeSelectorsRequest) (*datastore.SetNodeSelectorsResponse, error) {
	if err := s.getNextError(); err != nil {
		return nil, err
	}
	return s.ds.SetNodeSelectors(ctx, req)
}

func (s *DataStore) ListNodeSelectors(ctx context.Context, req *datastore.ListNodeSelectorsRequest) (*datastore.ListNodeSelectorsResponse, error) {
	if err := s.getNextError(); err != nil {
		return nil, err
	}
	return s.ds.ListNodeSelectors(ctx, req)
}

func (s *DataStore) GetNodeSelectors(ctx context.Context, req *datastore.GetNodeSelectorsRequest) (*datastore.GetNodeSelectorsResponse, error) {
	if err := s.getNextError(); err != nil {
		return nil, err
	}
	resp, err := s.ds.GetNodeSelectors(ctx, req)
	if err == nil {
		// Sorting helps unit-tests have deterministic assertions.
		util.SortSelectors(resp.Selectors.Selectors)
	}
	return resp, err
}

func (s *DataStore) CountRegistrationEntries(ctx context.Context) (int32, error) {
	if err := s.getNextError(); err != nil {
		return 0, err
	}
	return s.ds.CountRegistrationEntries(ctx)
}

func (s *DataStore) CreateRegistrationEntry(ctx context.Context, req *datastore.CreateRegistrationEntryRequest) (*datastore.CreateRegistrationEntryResponse, error) {
	if err := s.getNextError(); err != nil {
		return nil, err
	}
	return s.ds.CreateRegistrationEntry(ctx, req)
}

func (s *DataStore) FetchRegistrationEntry(ctx context.Context, req *datastore.FetchRegistrationEntryRequest) (*datastore.FetchRegistrationEntryResponse, error) {
	if err := s.getNextError(); err != nil {
		return nil, err
	}
	return s.ds.FetchRegistrationEntry(ctx, req)
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

func (s *DataStore) UpdateRegistrationEntry(ctx context.Context, req *datastore.UpdateRegistrationEntryRequest) (*datastore.UpdateRegistrationEntryResponse, error) {
	if err := s.getNextError(); err != nil {
		return nil, err
	}
	return s.ds.UpdateRegistrationEntry(ctx, req)
}

func (s *DataStore) DeleteRegistrationEntry(ctx context.Context, req *datastore.DeleteRegistrationEntryRequest) (*datastore.DeleteRegistrationEntryResponse, error) {
	if err := s.getNextError(); err != nil {
		return nil, err
	}
	return s.ds.DeleteRegistrationEntry(ctx, req)
}

func (s *DataStore) PruneRegistrationEntries(ctx context.Context, req *datastore.PruneRegistrationEntriesRequest) (*datastore.PruneRegistrationEntriesResponse, error) {
	if err := s.getNextError(); err != nil {
		return nil, err
	}
	return s.ds.PruneRegistrationEntries(ctx, req)
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
