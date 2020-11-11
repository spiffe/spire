package endpoints

import (
	"context"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/pkg/server/cache/entrycache"
	"github.com/spiffe/spire/pkg/server/plugin/datastore"
	"github.com/spiffe/spire/proto/spire/types"
	"github.com/spiffe/spire/test/clock"
)

const (
	cacheReloadInterval = 5 * time.Second
)

var _ api.AuthorizedEntryFetcher = (*AuthorizedEntryFetcherWithFullCache)(nil)

type AuthorizedEntryFetcherWithFullCache struct {
	cache   entrycache.Cache
	clk     clock.Clock
	ds      datastore.DataStore
	log     logrus.FieldLogger
	metrics telemetry.Metrics
	mu      sync.RWMutex
}

func NewAuthorizedEntryFetcherWithFullCache(ctx context.Context, log logrus.FieldLogger, metrics telemetry.Metrics, ds datastore.DataStore, clk clock.Clock) (*AuthorizedEntryFetcherWithFullCache, error) {
	cache, err := buildCache(ctx, metrics, ds)
	if err != nil {
		return nil, err
	}

	return &AuthorizedEntryFetcherWithFullCache{
		cache:   cache,
		clk:     clk,
		ds:      ds,
		log:     log,
		metrics: metrics,
	}, nil
}

func (a *AuthorizedEntryFetcherWithFullCache) FetchAuthorizedEntries(ctx context.Context, agentID spiffeid.ID) ([]*types.Entry, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.cache.GetAuthorizedEntries(agentID), nil
}

// RunRebuildCacheTask starts a ticker which rebuilds the in-memory entry cache.
func (a *AuthorizedEntryFetcherWithFullCache) RunRebuildCacheTask(ctx context.Context) error {
	t := a.clk.Ticker(cacheReloadInterval)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			a.log.Debug("Stopping in-memory entry cache hydrator")
			return nil
		case <-t.C:
			start := time.Now()
			cache, err := buildCache(ctx, a.metrics, a.ds)
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
		}
	}
}

func buildCache(ctx context.Context, metrics telemetry.Metrics, ds datastore.DataStore) (_ entrycache.Cache, err error) {
	call := telemetry.StartCall(metrics, telemetry.Entry, telemetry.Cache, telemetry.Reload)
	defer call.Done(&err)
	return entrycache.BuildFromDataStore(ctx, ds)
}
