package endpoints

import (
	"context"
	"errors"
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

type AuthorizedEntryFetcherWithFullCache struct {
	buildCache           entryCacheBuilderFn
	cache                entrycache.Cache
	clk                  clock.Clock
	log                  logrus.FieldLogger
	ds                   datastore.DataStore
	mu                   sync.RWMutex
	cacheReloadInterval  time.Duration
	pruneEventsOlderThan time.Duration
}

func NewAuthorizedEntryFetcherWithFullCache(ctx context.Context, buildCache entryCacheBuilderFn, log logrus.FieldLogger, clk clock.Clock, ds datastore.DataStore, cacheReloadInterval, pruneEventsOlderThan time.Duration) (*AuthorizedEntryFetcherWithFullCache, error) {
	log.Info("Building in-memory entry cache")
	cache, err := buildCache(ctx)
	if err != nil {
		return nil, err
	}

	log.Info("Completed building in-memory entry cache")
	return &AuthorizedEntryFetcherWithFullCache{
		buildCache:           buildCache,
		cache:                cache,
		clk:                  clk,
		log:                  log,
		ds:                   ds,
		cacheReloadInterval:  cacheReloadInterval,
		pruneEventsOlderThan: pruneEventsOlderThan,
	}, nil
}

func (a *AuthorizedEntryFetcherWithFullCache) LookupAuthorizedEntries(ctx context.Context, agentID spiffeid.ID, entryIDs map[string]struct{}) (map[string]*types.Entry, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.cache.LookupAuthorizedEntries(agentID, entryIDs), nil
}

func (a *AuthorizedEntryFetcherWithFullCache) FetchAuthorizedEntries(_ context.Context, agentID spiffeid.ID) ([]*types.Entry, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.cache.GetAuthorizedEntries(agentID), nil
}

// RunRebuildCacheTask starts a ticker which rebuilds the in-memory entry cache.
func (a *AuthorizedEntryFetcherWithFullCache) RunRebuildCacheTask(ctx context.Context) error {
	rebuild := func() {
		cache, err := a.buildCache(ctx)
		if err != nil {
			a.log.WithError(err).Error("Failed to reload entry cache")
		} else {
			a.mu.Lock()
			a.cache = cache
			a.mu.Unlock()
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

// PruneEventsTask start a ticker which prunes old events
func (a *AuthorizedEntryFetcherWithFullCache) PruneEventsTask(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			a.log.Debug("Stopping event pruner")
			return nil
		case <-a.clk.After(a.pruneEventsOlderThan / 2):
			a.log.Debug("Pruning events")
			if err := a.pruneEvents(ctx, a.pruneEventsOlderThan); err != nil {
				a.log.WithError(err).Error("Failed to prune events")
			}
		}
	}
}

func (a *AuthorizedEntryFetcherWithFullCache) pruneEvents(ctx context.Context, olderThan time.Duration) error {
	pruneRegistrationEntryEventsErr := a.ds.PruneRegistrationEntryEvents(ctx, olderThan)
	pruneAttestedNodeEventsErr := a.ds.PruneAttestedNodeEvents(ctx, olderThan)

	return errors.Join(pruneRegistrationEntryEventsErr, pruneAttestedNodeEventsErr)
}
