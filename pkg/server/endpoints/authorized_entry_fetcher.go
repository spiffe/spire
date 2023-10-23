package endpoints

import (
	"context"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/pkg/server/authorizedentries"
	"github.com/spiffe/spire/pkg/server/datastore"
)

var _ api.AuthorizedEntryFetcher = (*AuthorizedEntryFetcherWithEventsBasedCache)(nil)

type AuthorizedEntryFetcherWithEventsBasedCache struct {
	cache                *authorizedentries.Cache
	clk                  clock.Clock
	log                  logrus.FieldLogger
	ds                   datastore.DataStore
	cacheReloadInterval  time.Duration
	pruneEventsOlderThan time.Duration
	lastEventID          uint
}

func NewAuthorizedEntryFetcherWithEventsBasedCache(ctx context.Context, log logrus.FieldLogger, clk clock.Clock, ds datastore.DataStore, cacheReloadInterval, pruneEventsOlderThan time.Duration) (*AuthorizedEntryFetcherWithEventsBasedCache, error) {
	log.Info("Building in-memory entry cache")
	cache, err := buildCache(ctx, ds)
	if err != nil {
		return nil, err
	}
	log.Info("Completed building in-memory entry cache")

	return &AuthorizedEntryFetcherWithEventsBasedCache{
		cache:                cache,
		clk:                  clk,
		log:                  log,
		ds:                   ds,
		cacheReloadInterval:  cacheReloadInterval,
		pruneEventsOlderThan: pruneEventsOlderThan,
	}, nil
}

func (a *AuthorizedEntryFetcherWithEventsBasedCache) FetchAuthorizedEntries(_ context.Context, agentID spiffeid.ID) ([]*types.Entry, error) {
	return a.cache.GetAuthorizedEntries(agentID), nil
}

// RunUpdateCacheTask starts a ticker which rebuilds the in-memory entry cache.
func (a *AuthorizedEntryFetcherWithEventsBasedCache) RunUpdateCacheTask(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			a.log.Debug("Stopping in-memory entry cache hydrator")
			return nil
		case <-a.clk.After(a.cacheReloadInterval):
			err := a.updateCache(ctx)
			if err != nil {
				a.log.WithError(err).Error("Failed to update entry cache")
			}
		}
	}
}
func (a *AuthorizedEntryFetcherWithEventsBasedCache) PruneEventsTask(ctx context.Context) error {
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

func (a *AuthorizedEntryFetcherWithEventsBasedCache) pruneEvents(ctx context.Context, olderThan time.Duration) error {
	if err := a.ds.PruneRegistrationEntriesEvents(ctx, olderThan); err != nil {
		return err
	}
	return a.ds.PruneAttestedNodesEvents(ctx, olderThan)
}

func (a *AuthorizedEntryFetcherWithEventsBasedCache) updateCache(ctx context.Context) error {
	req := &datastore.ListRegistrationEntriesEventsRequest{
		GreaterThanEventID: a.lastEventID,
	}
	resp, err := a.ds.ListRegistrationEntriesEvents(ctx, req)
	if err != nil {
		return err
	}

	for _, entryID := range resp.EntryIDs {
		commonEntry, err := a.ds.FetchRegistrationEntry(ctx, entryID)
		if err != nil {
			return err
		}

		if commonEntry == nil {
			a.cache.RemoveEntry(entryID)
			a.lastEventID++
			continue
		}

		entry, err := api.RegistrationEntryToProto(commonEntry)
		if err != nil {
			return err
		}
		a.cache.UpdateEntry(entry)
		a.lastEventID++
	}

	return nil
}

func buildCache(ctx context.Context, ds datastore.DataStore) (*authorizedentries.Cache, error) {
	cache := authorizedentries.NewCache()

	if err := addEntries(ctx, ds, cache); err != nil {
		return nil, err
	}

	if err := addAgents(ctx, ds, cache); err != nil {
		return nil, err
	}

	return cache, nil
}

// Fetches all registration entries and adds them to the cache
func addEntries(ctx context.Context, ds datastore.DataStore, cache *authorizedentries.Cache) error {
	resp, err := ds.ListRegistrationEntries(ctx, &datastore.ListRegistrationEntriesRequest{
		DataConsistency: datastore.TolerateStale,
	})
	if err != nil {
		return err
	}

	entries, err := api.RegistrationEntriesToProto(resp.Entries)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		cache.UpdateEntry(entry)
	}

	return nil
}

// Fetches all attested nodes and adds the unexpired ones to the cache
func addAgents(ctx context.Context, ds datastore.DataStore, cache *authorizedentries.Cache) error {
	now := time.Now()
	resp, err := ds.ListAttestedNodes(ctx, &datastore.ListAttestedNodesRequest{
		FetchSelectors: true,
	})
	if err != nil {
		return err
	}

	for _, node := range resp.Nodes {
		agentExpiresAt := time.Unix(node.CertNotAfter, 0)
		if agentExpiresAt.Before(now) {
			continue
		}
		cache.UpdateAgent(node.SpiffeId, AgentExpiresAt, api.ProtoFromSelectors(node.Selectors))
	}

	return nil
}
