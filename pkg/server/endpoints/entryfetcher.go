package endpoints

import (
	"context"
	"sync"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/pkg/server/cache/entrycache"
)

var _ api.AuthorizedEntryFetcher = (*AuthorizedEntryFetcherWithFullCache)(nil)

type entryCacheBuilderFn func(ctx context.Context) (entrycache.Cache, error)

type AuthorizedEntryFetcherWithFullCache struct {
	buildCache          entryCacheBuilderFn
	cache               entrycache.Cache
	clk                 clock.Clock
	log                 logrus.FieldLogger
	mu                  sync.RWMutex
	cacheReloadInterval time.Duration
}

func NewAuthorizedEntryFetcherWithFullCache(ctx context.Context, buildCache entryCacheBuilderFn, log logrus.FieldLogger, clk clock.Clock, cacheReloadInterval time.Duration) (*AuthorizedEntryFetcherWithFullCache, error) {
	log.Info("Building in-memory entry cache")
	cache, err := buildCache(ctx)
	if err != nil {
		return nil, err
	}

	log.Info("Completed building in-memory entry cache")
	return &AuthorizedEntryFetcherWithFullCache{
		buildCache:          buildCache,
		cache:               cache,
		clk:                 clk,
		log:                 log,
		cacheReloadInterval: cacheReloadInterval,
	}, nil
}

func (a *AuthorizedEntryFetcherWithFullCache) FetchAuthorizedEntries(ctx context.Context, agentID spiffeid.ID) ([]*types.Entry, error) {
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
