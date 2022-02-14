package endpoints

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/pkg/server/cache/entrycache"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/clock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	trustDomain = spiffeid.RequireTrustDomainFromString("example.org")
)

var _ entrycache.Cache = (*staticEntryCache)(nil)

type staticEntryCache struct {
	entries map[spiffeid.ID][]*types.Entry
}

func (sef *staticEntryCache) GetAuthorizedEntries(agentID spiffeid.ID) []*types.Entry {
	return sef.entries[agentID]
}

func newStaticEntryCache(entries map[spiffeid.ID][]*types.Entry) *staticEntryCache {
	return &staticEntryCache{
		entries: entries,
	}
}

func TestNewAuthorizedEntryFetcherWithFullCache(t *testing.T) {
	ctx := context.Background()
	log, _ := test.NewNullLogger()
	clk := clock.NewMock(t)
	entries := make(map[spiffeid.ID][]*types.Entry)
	buildCache := func(context.Context) (entrycache.Cache, error) {
		return newStaticEntryCache(entries), nil
	}

	ef, err := NewAuthorizedEntryFetcherWithFullCache(ctx, buildCache, log, clk, defaultCacheReloadInterval)
	assert.NoError(t, err)
	assert.NotNil(t, ef)
}

func TestNewAuthorizedEntryFetcherWithFullCacheErrorBuildingCache(t *testing.T) {
	ctx := context.Background()
	log, _ := test.NewNullLogger()
	clk := clock.NewMock(t)

	buildCache := func(context.Context) (entrycache.Cache, error) {
		return nil, errors.New("some cache build error")
	}

	ef, err := NewAuthorizedEntryFetcherWithFullCache(ctx, buildCache, log, clk, defaultCacheReloadInterval)
	assert.Error(t, err)
	assert.Nil(t, ef)
}

func TestFetchRegistrationEntries(t *testing.T) {
	ctx := context.Background()
	log, _ := test.NewNullLogger()
	clk := clock.NewMock(t)
	agentID := spiffeid.RequireFromPath(trustDomain, "/root")
	expected := setupExpectedEntriesData(t, agentID)

	buildCacheFn := func(ctx context.Context) (entrycache.Cache, error) {
		entries := map[spiffeid.ID][]*types.Entry{
			agentID: expected,
		}

		return newStaticEntryCache(entries), nil
	}

	ef, err := NewAuthorizedEntryFetcherWithFullCache(ctx, buildCacheFn, log, clk, defaultCacheReloadInterval)
	require.NoError(t, err)
	require.NotNil(t, ef)

	entries, err := ef.FetchAuthorizedEntries(ctx, agentID)
	assert.NoError(t, err)
	assert.Equal(t, expected, entries)
}

func TestRunRebuildCacheTask(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	watchErr := make(chan error, 1)
	defer func() {
		cancel()
		select {
		case err := <-watchErr:
			assert.NoError(t, err)
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for watch to return")
		}
	}()

	log, _ := test.NewNullLogger()
	clk := clock.NewMock(t)
	agentID := spiffeid.RequireFromPath(trustDomain, "/root")
	var expectedEntries []*types.Entry

	type buildCacheResult struct {
		cache entrycache.Cache
		err   error
	}
	type buildCacheRequest struct {
		resultCh chan buildCacheResult
	}

	buildCacheCh := make(chan buildCacheRequest)
	// The first time the cache is built synchronously in the same goroutine as the test.
	// All subsequent cache rebuilds are handled by the entry fetcher in a separate goroutine.
	// For the first cache build only, we don't want to rely on the request-response mechanism
	// used for coordination between the test goroutine and the entry fetcher goroutine.
	isFirstCacheBuild := true
	buildCache := func(ctx context.Context) (entrycache.Cache, error) {
		if isFirstCacheBuild {
			isFirstCacheBuild = false
			emptyEntries := make(map[spiffeid.ID][]*types.Entry)
			return newStaticEntryCache(emptyEntries), nil
		}
		resultCh := make(chan buildCacheResult)
		// Block until the test is ready for hydration to occur (which it
		// does by reading on hydrateCh).
		req := buildCacheRequest{
			resultCh: resultCh,
		}
		select {
		case buildCacheCh <- req:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		// Wait for the test to provide the resultss
		select {
		case result := <-resultCh:
			return result.cache, result.err
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(5 * time.Second):
			return nil, errors.New("cache hydrate function timed out waiting for test to invoke it")
		}
	}

	ef, err := NewAuthorizedEntryFetcherWithFullCache(ctx, buildCache, log, clk, defaultCacheReloadInterval)
	require.NoError(t, err)
	require.NotNil(t, ef)

	go func() {
		watchErr <- ef.RunRebuildCacheTask(ctx)
	}()

	waitForRequest := func() buildCacheRequest {
		clk.WaitForAfter(time.Minute, "waiting for watch timer")
		clk.Add(defaultCacheReloadInterval)
		select {
		case request := <-buildCacheCh:
			return request
		case <-ctx.Done():
			t.Fatal("timed out waiting for the build cache request")
			return buildCacheRequest{} // unreachable
		}
	}

	sendResult := func(request buildCacheRequest, entries map[spiffeid.ID][]*types.Entry, err error) {
		if entries == nil {
			entries = make(map[spiffeid.ID][]*types.Entry)
		}

		result := buildCacheResult{
			cache: newStaticEntryCache(entries),
			err:   err,
		}
		select {
		case request.resultCh <- result:
		case <-ctx.Done():
			t.Fatal("timed out waiting to send the build cache result")
		}
	}

	// There should be no entries initially
	var req buildCacheRequest
	req = waitForRequest()
	entries, err := ef.FetchAuthorizedEntries(ctx, agentID)
	assert.NoError(t, err)
	assert.Empty(t, entries)
	buildCacheErr := errors.New("some cache build error")
	sendResult(req, nil, buildCacheErr)

	// Verify that rebuild task gracefully handles downstream errors and retries after the reload interval elapses again
	req = waitForRequest()
	entries, err = ef.FetchAuthorizedEntries(ctx, agentID)
	assert.NoError(t, err)
	assert.Empty(t, entries)
	expectedEntries = setupExpectedEntriesData(t, agentID)
	entryMap := map[spiffeid.ID][]*types.Entry{
		agentID: expectedEntries,
	}

	sendResult(req, entryMap, nil)

	// When the rebuild task is able to complete successfully,
	// the cache should now contain the Agent's new authorized entries
	req = waitForRequest()
	entries, err = ef.FetchAuthorizedEntries(ctx, agentID)
	assert.NoError(t, err)
	assert.Equal(t, expectedEntries, entries)
	sendResult(req, entryMap, nil)
}

func setupExpectedEntriesData(t *testing.T, agentID spiffeid.ID) []*types.Entry {
	const numEntries = 2
	entryIDs := make([]spiffeid.ID, numEntries)
	for i := 0; i < numEntries; i++ {
		entryIDs[i] = spiffeid.RequireFromPathf(trustDomain, "/%d", i)
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
