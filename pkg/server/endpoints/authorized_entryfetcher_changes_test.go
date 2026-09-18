package endpoints

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/pkg/server/authorizedentries"
	"github.com/spiffe/spire/pkg/server/cache/nodecache"
	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/fakes/fakedatastore"
	"github.com/spiffe/spire/test/fakes/fakemetrics"
	"github.com/stretchr/testify/require"
)

type hydrationFailingDataStore struct {
	datastore.DataStore
	failEntryHydration bool
	failNodeHydration  bool
}

func (ds *hydrationFailingDataStore) FetchRegistrationEntries(ctx context.Context, entryIDs []string) (map[string]*common.RegistrationEntry, error) {
	if ds.failEntryHydration {
		ds.failEntryHydration = false
		return nil, errors.New("entry hydration failed")
	}
	return ds.DataStore.FetchRegistrationEntries(ctx, entryIDs)
}

func (ds *hydrationFailingDataStore) ListAttestedNodes(ctx context.Context, req *datastore.ListAttestedNodesRequest) (*datastore.ListAttestedNodesResponse, error) {
	if ds.failNodeHydration && len(req.BySpiffeIDs) > 0 {
		ds.failNodeHydration = false
		return nil, errors.New("node hydration failed")
	}
	return ds.DataStore.ListAttestedNodes(ctx, req)
}

func TestRegistrationEntryHydrationQueueRetriesAndSurvivesCacheSwap(t *testing.T) {
	ctx := context.Background()
	log, _ := test.NewNullLogger()
	clk := clock.NewMock(t)
	baseDS := fakedatastore.New(t)
	ds := &hydrationFailingDataStore{DataStore: baseDS}
	cache := authorizedentries.NewCache(clk, "example.org")
	entries, err := buildRegistrationEntriesCache(ctx, log, fakemetrics.New(), ds, clk, cache, 100, time.Minute)
	require.NoError(t, err)

	entry, err := baseDS.CreateRegistrationEntry(ctx, &common.RegistrationEntry{
		SpiffeId:  "spiffe://example.org/workload",
		ParentId:  "spiffe://example.org/agent",
		Selectors: []*common.Selector{{Type: "unix", Value: "uid:1000"}},
	})
	require.NoError(t, err)
	ds.failEntryHydration = true
	require.Error(t, entries.updateCache(ctx))
	require.Contains(t, entries.fetchEntries, entry.EntryId)

	replacement := authorizedentries.NewCache(clk, "example.org")
	entries.swapCache(replacement)
	require.Contains(t, entries.fetchEntries, entry.EntryId)
	require.NoError(t, entries.updateCache(ctx))
	require.Empty(t, entries.fetchEntries)
	require.Equal(t, 1, replacement.Stats().EntriesByEntryID)

	_, err = baseDS.DeleteRegistrationEntry(ctx, entry.EntryId)
	require.NoError(t, err)
	require.NoError(t, entries.updateCache(ctx))
	require.Zero(t, replacement.Stats().EntriesByEntryID)
}

func TestAttestedNodeHydrationQueueRetriesAndRemovesDeletedNode(t *testing.T) {
	ctx := context.Background()
	log, _ := test.NewNullLogger()
	clk := clock.NewMock(t)
	baseDS := fakedatastore.New(t)
	ds := &hydrationFailingDataStore{DataStore: baseDS}
	cache := authorizedentries.NewCache(clk, "example.org")
	nodesCache, err := nodecache.New(ctx, log, baseDS, clk, false, true)
	require.NoError(t, err)
	nodes, err := buildAttestedNodesCache(ctx, log, fakemetrics.New(), ds, clk, cache, nodesCache, 100, time.Minute)
	require.NoError(t, err)

	spiffeID := "spiffe://example.org/agent"
	_, err = baseDS.CreateAttestedNode(ctx, &common.AttestedNode{
		SpiffeId:         spiffeID,
		CertSerialNumber: "serial",
		CertNotAfter:     time.Now().Add(time.Hour).Unix(),
	})
	require.NoError(t, err)
	ds.failNodeHydration = true
	require.Error(t, nodes.updateCache(ctx))
	require.Contains(t, nodes.fetchNodes, spiffeID)
	require.NoError(t, nodes.updateCache(ctx))
	require.Empty(t, nodes.fetchNodes)
	require.Equal(t, 1, cache.Stats().AgentsByID)

	_, err = baseDS.DeleteAttestedNode(ctx, spiffeID)
	require.NoError(t, err)
	require.NoError(t, nodes.updateCache(ctx))
	require.Zero(t, cache.Stats().AgentsByID)
}
