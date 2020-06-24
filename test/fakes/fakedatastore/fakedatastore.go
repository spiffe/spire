package fakedatastore

import (
	"context"
	"fmt"
	"sort"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/pkg/server/plugin/datastore"
	"github.com/spiffe/spire/pkg/server/plugin/datastore/sql"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
	"github.com/spiffe/spire/test/spiretest"
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
	var ds datastore.Plugin

	// TODO: clean up plugin when we move to go1.14.
	_ = spiretest.LoadPlugin(tb, sql.BuiltIn(), &ds)

	_, err := ds.Configure(context.Background(), &spi.ConfigureRequest{
		Configuration: fmt.Sprintf(`
			database_type = "sqlite3"
			connection_string = "file:memdb%d?mode=memory&cache=shared"
		`, atomic.AddUint32(&nextID, 1)),
	})
	require.NoError(tb, err)

	return &DataStore{
		ds: ds,
	}
}

func (s *DataStore) CreateBundle(ctx context.Context, req *datastore.CreateBundleRequest) (*datastore.CreateBundleResponse, error) {
	if err := s.getNextError(); err != nil {
		return nil, err
	}
	return s.ds.CreateBundle(ctx, req)
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

func (s *DataStore) DeleteBundle(ctx context.Context, req *datastore.DeleteBundleRequest) (*datastore.DeleteBundleResponse, error) {
	if err := s.getNextError(); err != nil {
		return nil, err
	}
	return s.ds.DeleteBundle(ctx, req)
}

func (s *DataStore) FetchBundle(ctx context.Context, req *datastore.FetchBundleRequest) (*datastore.FetchBundleResponse, error) {
	if err := s.getNextError(); err != nil {
		return nil, err
	}
	return s.ds.FetchBundle(ctx, req)
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

func (s *DataStore) CreateAttestedNode(ctx context.Context, req *datastore.CreateAttestedNodeRequest) (*datastore.CreateAttestedNodeResponse, error) {
	if err := s.getNextError(); err != nil {
		return nil, err
	}
	return s.ds.CreateAttestedNode(ctx, req)
}

func (s *DataStore) FetchAttestedNode(ctx context.Context, req *datastore.FetchAttestedNodeRequest) (*datastore.FetchAttestedNodeResponse, error) {
	if err := s.getNextError(); err != nil {
		return nil, err
	}
	return s.ds.FetchAttestedNode(ctx, req)
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

func (s *DataStore) DeleteAttestedNode(ctx context.Context, req *datastore.DeleteAttestedNodeRequest) (*datastore.DeleteAttestedNodeResponse, error) {
	if err := s.getNextError(); err != nil {
		return nil, err
	}
	return s.ds.DeleteAttestedNode(ctx, req)
}

func (s *DataStore) SetNodeSelectors(ctx context.Context, req *datastore.SetNodeSelectorsRequest) (*datastore.SetNodeSelectorsResponse, error) {
	if err := s.getNextError(); err != nil {
		return nil, err
	}
	return s.ds.SetNodeSelectors(ctx, req)
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

func (s *DataStore) CreateJoinToken(ctx context.Context, req *datastore.CreateJoinTokenRequest) (*datastore.CreateJoinTokenResponse, error) {
	if err := s.getNextError(); err != nil {
		return nil, err
	}
	return s.ds.CreateJoinToken(ctx, req)
}

func (s *DataStore) FetchJoinToken(ctx context.Context, req *datastore.FetchJoinTokenRequest) (*datastore.FetchJoinTokenResponse, error) {
	if err := s.getNextError(); err != nil {
		return nil, err
	}
	return s.ds.FetchJoinToken(ctx, req)
}

func (s *DataStore) DeleteJoinToken(ctx context.Context, req *datastore.DeleteJoinTokenRequest) (*datastore.DeleteJoinTokenResponse, error) {
	if err := s.getNextError(); err != nil {
		return nil, err
	}
	return s.ds.DeleteJoinToken(ctx, req)
}

func (s *DataStore) PruneJoinTokens(ctx context.Context, req *datastore.PruneJoinTokensRequest) (*datastore.PruneJoinTokensResponse, error) {
	if err := s.getNextError(); err != nil {
		return nil, err
	}
	return s.ds.PruneJoinTokens(ctx, req)
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

func (s *DataStore) Configure(ctx context.Context, req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	return &spi.ConfigureResponse{}, nil
}

func (s *DataStore) GetPluginInfo(context.Context, *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &spi.GetPluginInfoResponse{}, nil
}
