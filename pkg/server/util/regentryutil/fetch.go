package regentryutil

import (
	"context"
	"errors"
	"time"

	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/pkg/server/plugin/datastore"
	"github.com/spiffe/spire/proto/spire/common"
)

const cacheFetchEntriesTTL = 1 * time.Second

func FetchRegistrationEntriesWithCache(ctx context.Context, dataStore datastore.DataStore, cache RegistrationEntriesCache, spiffeID string) ([]*common.RegistrationEntry, error) {
	fetcher := newRegistrationEntryFetcher(dataStore, cache)
	return fetcher.Fetch(ctx, spiffeID)
}

func FetchRegistrationEntries(ctx context.Context, dataStore datastore.DataStore, spiffeID string) ([]*common.RegistrationEntry, error) {
	fetcher := newRegistrationEntryFetcher(dataStore, &nullCache{})
	return fetcher.Fetch(ctx, spiffeID)
}

type registrationEntryFetcher struct {
	dataStore datastore.DataStore
	cache     RegistrationEntriesCache
}

func newRegistrationEntryFetcher(dataStore datastore.DataStore, cache RegistrationEntriesCache) *registrationEntryFetcher {
	return &registrationEntryFetcher{
		dataStore: dataStore,
		cache:     cache,
	}
}

func (f *registrationEntryFetcher) Fetch(ctx context.Context, id string) ([]*common.RegistrationEntry, error) {
	var entries []*common.RegistrationEntry
	var err error
	visited := make(map[string]bool)
	entries, err = f.fetch(ctx, id, visited, false)
	if err != nil {
		return nil, err
	}
	return util.DedupRegistrationEntries(entries), nil
}

func (f *registrationEntryFetcher) fetch(ctx context.Context, id string, visited map[string]bool, shouldCache bool) ([]*common.RegistrationEntry, error) {
	if visited[id] {
		return nil, nil
	}
	visited[id] = true

	cachedEntries, ok := f.cache.Get(id)
	if ok {
		return cachedEntries, nil
	}

	directEntries, err := f.directEntries(ctx, id)
	if err != nil {
		return nil, err
	}

	entries := directEntries
	for _, directEntry := range directEntries {
		descendantEntries, err := f.fetch(ctx, directEntry.SpiffeId, visited, true)
		if err != nil {
			return nil, err
		}
		entries = append(entries, descendantEntries...)
	}

	if shouldCache {
		f.cache.AddWithExpire(id, entries, cacheFetchEntriesTTL)
	}
	return entries, nil
}

// directEntries queries the datastore to determine the registration entries
// the provided ID is immediately authorized to issue.
func (f *registrationEntryFetcher) directEntries(ctx context.Context, id string) ([]*common.RegistrationEntry, error) {
	childEntries, err := f.childEntries(ctx, id)
	if err != nil {
		return nil, err
	}

	mappedEntries, err := f.mappedEntries(ctx, id)
	if err != nil {
		return nil, err
	}

	return append(childEntries, mappedEntries...), nil
}

// childEntries returns all registration entries for which the given ID is
// defined as a parent.
func (f *registrationEntryFetcher) childEntries(ctx context.Context, clientID string) ([]*common.RegistrationEntry, error) {
	resp, err := f.dataStore.ListRegistrationEntries(ctx,
		&datastore.ListRegistrationEntriesRequest{
			ByParentId: &wrappers.StringValue{
				Value: clientID,
			},
			TolerateStale: true,
		})
	if err != nil {
		return nil, err
	}

	return resp.Entries, nil
}

// mappedEntries returns all registration entries for which the given ID has
// been mapped to by a node resolver.
func (f *registrationEntryFetcher) mappedEntries(ctx context.Context, clientID string) ([]*common.RegistrationEntry, error) {
	selectorsResp, err := f.dataStore.GetNodeSelectors(ctx,
		&datastore.GetNodeSelectorsRequest{
			SpiffeId:      clientID,
			TolerateStale: true,
		})
	if err != nil {
		return nil, err
	}
	if selectorsResp.Selectors == nil {
		return nil, errors.New("response missing selectors")
	}

	// No need to look for more entries if we didn't get any selectors
	selectors := selectorsResp.Selectors.Selectors
	if len(selectors) < 1 {
		return nil, nil
	}

	// list all registration entries with a combination of the selectors
	listResp, err := f.dataStore.ListRegistrationEntries(ctx,
		&datastore.ListRegistrationEntriesRequest{
			BySelectors: &datastore.BySelectors{
				Selectors: selectors,
				Match:     datastore.BySelectors_MATCH_SUBSET,
			},
			TolerateStale: true,
		})
	if err != nil {
		return nil, err
	}

	return listResp.Entries, nil
}

type nullCache struct {
}

func (c *nullCache) Get(key string) ([]*common.RegistrationEntry, bool) {
	return nil, false
}

func (c *nullCache) AddWithExpire(key string, value []*common.RegistrationEntry, expire time.Duration) {
}
