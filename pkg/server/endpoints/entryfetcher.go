package endpoints

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/pkg/server/cache/entrycache"
	"github.com/spiffe/spire/pkg/server/datastore"
)

var _ api.AuthorizedEntryFetcher = (*AuthorizedEntryFetcherWithFullCache)(nil)

type entryCacheBuilderFn func(ctx context.Context) (entrycache.Cache, error)
type entryCacheUpdateFn func(ctx context.Context, cache entrycache.Cache) error

type AuthorizedEntryFetcherWithFullCache struct {
	updateCache              entryCacheUpdateFn
	cache                    entrycache.Cache
	clk                      clock.Clock
	log                      logrus.FieldLogger
	mu                       sync.RWMutex
	dataStore                datastore.DataStore
	cacheReloadInterval      time.Duration
	cachePruneEventsInterval time.Duration
}

func NewAuthorizedEntryFetcherWithFullCache(ctx context.Context, buildCache entryCacheBuilderFn, updateCache entryCacheUpdateFn, c Config) (*AuthorizedEntryFetcherWithFullCache, error) {
	c.Log.Info("Building in-memory entry cache")
	cache, err := buildCache(ctx)
	if err != nil {
		return nil, err
	}

	c.Log.Info("Completed building in-memory entry cache")
	return &AuthorizedEntryFetcherWithFullCache{
		updateCache:              updateCache,
		cache:                    cache,
		clk:                      c.Clock,
		log:                      c.Log,
		dataStore:                c.Catalog.GetDataStore(),
		cacheReloadInterval:      c.CacheReloadInterval,
		cachePruneEventsInterval: c.CachePruneEventsInterval,
	}, nil
}

func (a *AuthorizedEntryFetcherWithFullCache) FetchAuthorizedEntries(ctx context.Context, agentID spiffeid.ID) ([]*types.Entry, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.cache.GetAuthorizedEntries(agentID), nil
}

func (a *AuthorizedEntryFetcherWithFullCache) FetchAllCachedEntries() ([]*types.Entry, error) {
	return a.cache.GetAllEntries(), nil
}

// RunRebuildCacheTask starts a ticker which rebuilds the in-memory entry cache.
func (a *AuthorizedEntryFetcherWithFullCache) RunRebuildCacheTask(ctx context.Context) error {
	rebuild := func() {
		a.mu.Lock()
		defer a.mu.Unlock()
		if err := a.updateCache(ctx, a.cache); err != nil {
			a.log.WithError(err).Error("Failed to reload entry cache")
		}

		entries, err := a.FetchAllCachedEntries()
		if err != nil {
			a.log.WithError(err).Error("Failed to get cache")
			return
		}
		for _, entry := range entries {
			printEntry(entry)
		}
	}

	for {
		select {
		case <-ctx.Done():
			a.log.Debug("Stopping in-memory entry cache hydrator")
			return nil
		case <-a.clk.After(a.cacheReloadInterval):
			rebuild()
		}
	}
}

func (a *AuthorizedEntryFetcherWithFullCache) RunPruneEventsTask(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			a.log.Debug("Stopping event pruner")
			return nil
		case <-a.clk.After(a.cachePruneEventsInterval):
			a.log.Info("Pruning events")
			if err := a.pruneEvents(ctx); err != nil {
				a.log.WithError(err).Error("Failed to prune events")
			}
		}
	}
}

func (a *AuthorizedEntryFetcherWithFullCache) pruneEvents(ctx context.Context) error {
	return a.dataStore.PruneEvents(ctx, a.cachePruneEventsInterval)

}

func printEntry(e *types.Entry) {
	fmt.Printf("Entry ID         : %s\n", printableEntryID(e.Id))
	fmt.Printf("SPIFFE ID        : %s\n", protoToIDString(e.SpiffeId))
	fmt.Printf("Parent ID        : %s\n", protoToIDString(e.ParentId))
	fmt.Printf("Revision         : %d\n", e.RevisionNumber)
	fmt.Printf("\n")
}

func printableEntryID(id string) string {
	if id == "" {
		return "(none)"
	}
	return id
}

// protoToIDString converts a SPIFFE ID from the given *types.SPIFFEID to string
func protoToIDString(id *types.SPIFFEID) string {
	if id == nil {
		return ""
	}
	return fmt.Sprintf("spiffe://%s%s", id.TrustDomain, id.Path)
}
