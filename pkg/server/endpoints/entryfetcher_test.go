package endpoints

import (
	"context"
	"errors"
	"strconv"
	"testing"

	"github.com/andres-erbsen/clock"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/pkg/server/cache/entrycache"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/proto/spire/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	trustDomain = spiffeid.RequireTrustDomainFromString("example.org")
)

var _ entrycache.Cache = (*staticEntryFetcher)(nil)

type staticEntryFetcher struct {
	entries map[spiffeid.ID][]*types.Entry
}

func (sef *staticEntryFetcher) GetAuthorizedEntries(agentID spiffeid.ID) []*types.Entry {
	return sef.entries[agentID]
}

func newStaticEntryFetcher(entries map[spiffeid.ID][]*types.Entry) *staticEntryFetcher {
	return &staticEntryFetcher{
		entries: entries,
	}
}

func TestNewAuthorizedEntryFetcherWithFullCache(t *testing.T) {
	ctx := context.Background()
	log, _ := test.NewNullLogger()
	clk := clock.NewMock()
	entries := make(map[spiffeid.ID][]*types.Entry)
	buildCache := func(context.Context) (entrycache.Cache, error) {
		return newStaticEntryFetcher(entries), nil
	}

	ef, err := NewAuthorizedEntryFetcherWithFullCache(ctx, buildCache, log, clk)
	assert.NoError(t, err)
	assert.NotNil(t, ef)
}

func TestNewAuthorizedEntryFetcherWithFullCacheErrorBuildingCache(t *testing.T) {
	ctx := context.Background()
	log, _ := test.NewNullLogger()
	clk := clock.NewMock()

	buildCache := func(context.Context) (entrycache.Cache, error) {
		return nil, errors.New("some cache build error")
	}

	ef, err := NewAuthorizedEntryFetcherWithFullCache(ctx, buildCache, log, clk)
	assert.Error(t, err)
	assert.Nil(t, ef)
}

func TestFetchRegistrationEntries(t *testing.T) {
	ctx := context.Background()
	log, _ := test.NewNullLogger()
	clk := clock.NewMock()
	agentID := trustDomain.NewID("/root")
	expected := setupExpectedEntriesData(t, agentID)

	buildCacheFn := func(ctx context.Context) (entrycache.Cache, error) {
		entries := map[spiffeid.ID][]*types.Entry{
			agentID: expected,
		}

		return newStaticEntryFetcher(entries), nil
	}

	ef, err := NewAuthorizedEntryFetcherWithFullCache(ctx, buildCacheFn, log, clk)
	require.NoError(t, err)
	require.NotNil(t, ef)

	entries, err := ef.FetchAuthorizedEntries(ctx, agentID)
	assert.NoError(t, err)
	assert.Equal(t, expected, entries)
}

func TestRunRebuildCacheTask(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	log, _ := test.NewNullLogger()
	clk := clock.NewMock()
	agentID := trustDomain.NewID("/root")
	var expectedEntries []*types.Entry
	var returnErr error

	buildCache := func(context.Context) (entrycache.Cache, error) {
		if returnErr != nil {
			return nil, returnErr
		}

		entryMap := map[spiffeid.ID][]*types.Entry{
			agentID: expectedEntries,
		}

		return newStaticEntryFetcher(entryMap), nil
	}

	ef, err := NewAuthorizedEntryFetcherWithFullCache(ctx, buildCache, log, clk)
	require.NoError(t, err)
	require.NotNil(t, ef)

	errChan := make(chan error, 1)
	go func() {
		errChan <- ef.RunRebuildCacheTask(ctx)
	}()

	entries, err := ef.FetchAuthorizedEntries(ctx, agentID)
	assert.NoError(t, err)
	assert.Empty(t, entries)

	expectedEntries = setupExpectedEntriesData(t, agentID)

	// Entries should still not be in the cache yet
	// because the clock has not elapsed long enough for the cache rebuild task to execute.
	entries, err = ef.FetchAuthorizedEntries(ctx, agentID)
	assert.NoError(t, err)
	assert.Empty(t, entries)

	// Verify that rebuild task gracefully handles downstream errors and retries after the reload interval elapses again
	returnErr = errors.New("some cache build error")
	clk.Add(cacheReloadInterval)
	entries, err = ef.FetchAuthorizedEntries(ctx, agentID)
	assert.NoError(t, err)
	assert.Empty(t, entries)

	// When the rebuild task is able to complete successfully,
	// the cache should now contain the Agent's new authorized entries
	returnErr = nil
	clk.Add(cacheReloadInterval)
	entries, err = ef.FetchAuthorizedEntries(ctx, agentID)
	assert.NoError(t, err)
	assert.Equal(t, expectedEntries, entries)

	cancel()
	assert.NoError(t, <-errChan)
}

func setupExpectedEntriesData(t *testing.T, agentID spiffeid.ID) []*types.Entry {
	const numEntries = 2
	entryIDs := make([]spiffeid.ID, numEntries)
	for i := 0; i < numEntries; i++ {
		entryIDs[i] = trustDomain.NewID(strconv.Itoa(i))
	}

	irrelevantSelectors := []*common.Selector{
		{
			Type:  "foo",
			Value: "bar",
		},
	}

	entries := []*common.RegistrationEntry{
		{
			ParentId:  agentID.String(),
			SpiffeId:  entryIDs[0].String(),
			Selectors: irrelevantSelectors,
		},
		{
			ParentId:  agentID.String(),
			SpiffeId:  entryIDs[1].String(),
			Selectors: irrelevantSelectors,
		},
	}

	expected, err := api.RegistrationEntriesToProto(entries)
	require.NoError(t, err)

	return expected
}
