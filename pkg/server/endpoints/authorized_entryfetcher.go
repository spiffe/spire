package endpoints

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/pkg/server/authorizedentries"
	"github.com/spiffe/spire/pkg/server/cache/nodecache"
	"github.com/spiffe/spire/pkg/server/datastore"
)

var _ api.AuthorizedEntryFetcher = (*AuthorizedEntryFetcherEvents)(nil)

const pageSize = 10000

type AuthorizedEntryFetcherEventsConfig struct {
	clk                     clock.Clock
	log                     logrus.FieldLogger
	cacheReloadInterval     time.Duration
	fullCacheReloadInterval time.Duration
	pruneEventsOlderThan    time.Duration
	eventTimeout            time.Duration
	ds                      datastore.DataStore
	nodeCache               *nodecache.Cache
	metrics                 telemetry.Metrics
}

type AuthorizedEntryFetcherEvents struct {
	c                   AuthorizedEntryFetcherEventsConfig
	cache               *authorizedentries.Cache
	registrationEntries eventsBasedCache
	attestedNodes       eventsBasedCache
	mu                  sync.RWMutex
}

type eventsBasedCache interface {
	updateCache(ctx context.Context) error
}

func NewAuthorizedEntryFetcherEvents(ctx context.Context, c AuthorizedEntryFetcherEventsConfig) (*AuthorizedEntryFetcherEvents, error) {
	authorizedEntryFetcher := &AuthorizedEntryFetcherEvents{
		c: c,
	}

	c.log.Info("Building event-based in-memory entry cache")
	if err := authorizedEntryFetcher.buildCache(ctx); err != nil {
		return nil, err
	}
	c.log.Info("Completed building event-based in-memory entry cache")

	return authorizedEntryFetcher, nil
}

func (a *AuthorizedEntryFetcherEvents) LookupAuthorizedEntries(ctx context.Context, agentID spiffeid.ID, entryIDs map[string]struct{}) (map[string]api.ReadOnlyEntry, error) {
	a.mu.RLock()
	cache := a.cache
	a.mu.RUnlock()

	return cache.LookupAuthorizedEntries(agentID, entryIDs), nil
}

func (a *AuthorizedEntryFetcherEvents) FetchAuthorizedEntries(_ context.Context, agentID spiffeid.ID) ([]api.ReadOnlyEntry, error) {
	a.mu.RLock()
	cache := a.cache
	a.mu.RUnlock()

	return cache.GetAuthorizedEntries(agentID), nil
}

// RunUpdateCacheTask starts a ticker which rebuilds the in-memory entry cache.
func (a *AuthorizedEntryFetcherEvents) RunUpdateCacheTask(ctx context.Context) error {
	var fullCacheReload bool

	cacheReloadTicker, fullCacheReloadTicker := a.startTickers()
	defer cacheReloadTicker.Stop()
	defer fullCacheReloadTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			a.c.log.Debug("Stopping in-memory entry cache hydrator")
			return ctx.Err()
		case <-cacheReloadTicker.C:
			if fullCacheReload {
				if err := a.buildCache(ctx); err != nil {
					a.c.log.WithError(err).Error("Failed to full refresh entry cache")
					continue
				}
				fullCacheReload = false
			} else {
				if err := a.updateCache(ctx); err != nil {
					a.c.log.WithError(err).Error("Failed to update entry cache")
				}
				if pruned := a.cache.PruneExpiredAgents(); pruned > 0 {
					a.c.log.WithField("count", pruned).Debug("Pruned expired agents from entry cache")
				}
			}
		case <-fullCacheReloadTicker.C:
			fullCacheReload = true
		}
	}
}

// PruneEventsTask start a ticker which prunes old events
func (a *AuthorizedEntryFetcherEvents) PruneEventsTask(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			a.c.log.Debug("Stopping event pruner")
			return ctx.Err()
		case <-a.c.clk.After(a.c.pruneEventsOlderThan / 2):
			a.c.log.Debug("Pruning events")
			if err := a.pruneEvents(ctx, a.c.pruneEventsOlderThan); err != nil {
				a.c.log.WithError(err).Error("Failed to prune events")
			}
		}
	}
}

func (a *AuthorizedEntryFetcherEvents) pruneEvents(ctx context.Context, olderThan time.Duration) error {
	pruneRegistrationEntryEventsErr := a.c.ds.PruneRegistrationEntryEvents(ctx, olderThan)
	pruneAttestedNodeEventsErr := a.c.ds.PruneAttestedNodeEvents(ctx, olderThan)

	return errors.Join(pruneRegistrationEntryEventsErr, pruneAttestedNodeEventsErr)
}

func (a *AuthorizedEntryFetcherEvents) updateCache(ctx context.Context) error {
	updateRegistrationEntriesCacheErr := a.registrationEntries.updateCache(ctx)
	updateAttestedNodesCacheErr := a.attestedNodes.updateCache(ctx)

	return errors.Join(updateRegistrationEntriesCacheErr, updateAttestedNodesCacheErr)
}

func (a *AuthorizedEntryFetcherEvents) buildCache(ctx context.Context) error {
	cache := authorizedentries.NewCache(a.c.clk)

	registrationEntries, err := buildRegistrationEntriesCache(ctx, a.c.log, a.c.metrics, a.c.ds, a.c.clk, cache, pageSize, a.c.cacheReloadInterval, a.c.eventTimeout)
	if err != nil {
		return err
	}

	attestedNodes, err := buildAttestedNodesCache(ctx, a.c.log, a.c.metrics, a.c.ds, a.c.clk, cache, a.c.nodeCache, a.c.cacheReloadInterval, a.c.eventTimeout)
	if err != nil {
		return err
	}

	a.mu.Lock()
	a.cache = cache
	a.mu.Unlock()

	a.registrationEntries = registrationEntries
	a.attestedNodes = attestedNodes

	return nil
}

func (a *AuthorizedEntryFetcherEvents) startTickers() (*clock.Ticker, *clock.Ticker) {
	cacheReloadTicker := a.c.clk.Ticker(a.c.cacheReloadInterval)
	fullCacheReloadTicker := a.c.clk.Ticker(a.c.fullCacheReloadInterval)

	return cacheReloadTicker, fullCacheReloadTicker
}
