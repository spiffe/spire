package endpoints

import (
	"context"
	"sync"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/pkg/server/cache/entrycache"
	"github.com/spiffe/spire/proto/spire/types"
)

const (
	cacheReloadInterval = 5 * time.Second
)

var _ api.AuthorizedEntryFetcher = (*AuthorizedEntryFetcherWithFullCache)(nil)

type entryCacheBuilderFn func(ctx context.Context) (entrycache.Cache, error)

type AuthorizedEntryFetcherWithFullCache struct {
	buildCache entryCacheBuilderFn
	cache      entrycache.Cache
	clk        clock.Clock
	log        logrus.FieldLogger
	mu         sync.RWMutex
}

func NewAuthorizedEntryFetcherWithFullCache(ctx context.Context, buildCache entryCacheBuilderFn, log logrus.FieldLogger, clk clock.Clock) (*AuthorizedEntryFetcherWithFullCache, error) {
	cache, err := buildCache(ctx)
	if err != nil {
		return nil, err
	}

	return &AuthorizedEntryFetcherWithFullCache{
		buildCache: buildCache,
		cache:      cache,
		clk:        clk,
		log:        log,
	}, nil
}

func (a *AuthorizedEntryFetcherWithFullCache) FetchAuthorizedEntries(ctx context.Context, agentID spiffeid.ID) ([]*types.Entry, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.cache.GetAuthorizedEntries(agentID), nil
}

// RunRebuildCacheTask starts a ticker which rebuilds the in-memory entry cache.
func (a *AuthorizedEntryFetcherWithFullCache) RunRebuildCacheTask(ctx context.Context) error {
	t := a.clk.Timer(cacheReloadInterval)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			a.log.Debug("Stopping in-memory entry cache hydrator")
			return nil
		case <-t.C:
			start := time.Now()
			cache, err := a.buildCache(ctx)
			end := time.Now()
			hydrateLog := a.log.WithField(telemetry.ElapsedTime, end.Sub(start))
			if err != nil {
				hydrateLog.WithError(err).Error("Failed to reload entry cache")
			} else {
				hydrateLog.Debug("Reloaded entry cache")
				a.mu.Lock()
				a.cache = cache
				a.mu.Unlock()
			}

			t.Reset(cacheReloadInterval)
		}
	}
}
