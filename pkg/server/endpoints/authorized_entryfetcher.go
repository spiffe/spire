package endpoints

import (
	"context"
	"errors"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/pkg/server/authorizedentries"
	"github.com/spiffe/spire/pkg/server/datastore"
)

var _ api.AuthorizedEntryFetcher = (*AuthorizedEntryFetcherWithEventsBasedCache)(nil)

const pageSize = 10000

type AuthorizedEntryFetcherWithEventsBasedCache struct {
	cache *authorizedentries.Cache
	clk   clock.Clock
	log   logrus.FieldLogger
	ds    datastore.DataStore

	cacheReloadInterval  time.Duration
	pruneEventsOlderThan time.Duration

	registrationEntries eventsBasedCache
	attestedNodes       eventsBasedCache
}

type eventsBasedCache interface {
	updateCache(ctx context.Context) error
}

func NewAuthorizedEntryFetcherWithEventsBasedCache(ctx context.Context, log logrus.FieldLogger, metrics telemetry.Metrics, clk clock.Clock, ds datastore.DataStore, cacheReloadInterval, pruneEventsOlderThan, sqlTransactionTimeout time.Duration) (*AuthorizedEntryFetcherWithEventsBasedCache, error) {
	log.Info("Building event-based in-memory entry cache")
	cache, registrationEntries, attestedNodes, err := buildCache(ctx, log, metrics, ds, clk, cacheReloadInterval, sqlTransactionTimeout)
	if err != nil {
		return nil, err
	}
	log.Info("Completed building event-based in-memory entry cache")

	return &AuthorizedEntryFetcherWithEventsBasedCache{
		cache:                cache,
		clk:                  clk,
		log:                  log,
		ds:                   ds,
		cacheReloadInterval:  cacheReloadInterval,
		pruneEventsOlderThan: pruneEventsOlderThan,
		registrationEntries:  registrationEntries,
		attestedNodes:        attestedNodes,
	}, nil
}

func (a *AuthorizedEntryFetcherWithEventsBasedCache) LookupAuthorizedEntries(ctx context.Context, agentID spiffeid.ID, entryIDs map[string]struct{}) (map[string]api.ReadOnlyEntry, error) {
	return a.cache.LookupAuthorizedEntries(agentID, entryIDs), nil
}

func (a *AuthorizedEntryFetcherWithEventsBasedCache) FetchAuthorizedEntries(_ context.Context, agentID spiffeid.ID) ([]api.ReadOnlyEntry, error) {
	return a.cache.GetAuthorizedEntries(agentID), nil
}

// RunUpdateCacheTask starts a ticker which rebuilds the in-memory entry cache.
func (a *AuthorizedEntryFetcherWithEventsBasedCache) RunUpdateCacheTask(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			a.log.Debug("Stopping in-memory entry cache hydrator")
			return ctx.Err()
		case <-a.clk.After(a.cacheReloadInterval):
			if err := a.updateCache(ctx); err != nil {
				a.log.WithError(err).Error("Failed to update entry cache")
			}
			if pruned := a.cache.PruneExpiredAgents(); pruned > 0 {
				a.log.WithField("count", pruned).Debug("Pruned expired agents from entry cache")
			}
		}
	}
}

// PruneEventsTask start a ticker which prunes old events
func (a *AuthorizedEntryFetcherWithEventsBasedCache) PruneEventsTask(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			a.log.Debug("Stopping event pruner")
			return ctx.Err()
		case <-a.clk.After(a.pruneEventsOlderThan / 2):
			a.log.Debug("Pruning events")
			if err := a.pruneEvents(ctx, a.pruneEventsOlderThan); err != nil {
				a.log.WithError(err).Error("Failed to prune events")
			}
		}
	}
}

func (a *AuthorizedEntryFetcherWithEventsBasedCache) pruneEvents(ctx context.Context, olderThan time.Duration) error {
	pruneRegistrationEntryEventsErr := a.ds.PruneRegistrationEntryEvents(ctx, olderThan)
	pruneAttestedNodeEventsErr := a.ds.PruneAttestedNodeEvents(ctx, olderThan)

	return errors.Join(pruneRegistrationEntryEventsErr, pruneAttestedNodeEventsErr)
}

func (a *AuthorizedEntryFetcherWithEventsBasedCache) updateCache(ctx context.Context) error {
	updateRegistrationEntriesCacheErr := a.registrationEntries.updateCache(ctx)
	updateAttestedNodesCacheErr := a.attestedNodes.updateCache(ctx)

	return errors.Join(updateRegistrationEntriesCacheErr, updateAttestedNodesCacheErr)
}

func buildCache(ctx context.Context, log logrus.FieldLogger, metrics telemetry.Metrics, ds datastore.DataStore, clk clock.Clock, cacheReloadInterval, eventTimeout time.Duration) (*authorizedentries.Cache, *registrationEntries, *attestedNodes, error) {
	cache := authorizedentries.NewCache(clk)

	registrationEntries, err := buildRegistrationEntriesCache(ctx, log, metrics, ds, clk, cache, pageSize, cacheReloadInterval, eventTimeout)
	if err != nil {
		return nil, nil, nil, err
	}

	attestedNodes, err := buildAttestedNodesCache(ctx, log, metrics, ds, clk, cache, cacheReloadInterval, eventTimeout)
	if err != nil {
		return nil, nil, nil, err
	}

	return cache, registrationEntries, attestedNodes, nil
}
