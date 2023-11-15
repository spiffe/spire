package endpoints

import (
	"context"
	"errors"
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
	cache                        *authorizedentries.Cache
	clk                          clock.Clock
	log                          logrus.FieldLogger
	ds                           datastore.DataStore
	cacheReloadInterval          time.Duration
	pruneEventsOlderThan         time.Duration
	lastRegistrationEntryEventID uint
	lastAttestedNodeEventID      uint
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
	pruneRegistrationEntriesEventsErr := a.ds.PruneRegistrationEntriesEvents(ctx, olderThan)
	pruneAttestedNodesEventsErr := a.ds.PruneAttestedNodesEvents(ctx, olderThan)

	return errors.Join(pruneRegistrationEntriesEventsErr, pruneAttestedNodesEventsErr)
}

func (a *AuthorizedEntryFetcherWithEventsBasedCache) updateCache(ctx context.Context) error {
	updateRegistrationEntriesCacheErr := a.updateRegistrationEntriesCache(ctx)
	updateAttestedNodesCacheErr := a.updateAttestedNodesCache(ctx)

	return errors.Join(updateRegistrationEntriesCacheErr, updateAttestedNodesCacheErr)
}

func (a *AuthorizedEntryFetcherWithEventsBasedCache) updateRegistrationEntriesCache(ctx context.Context) error {
	req := &datastore.ListRegistrationEntriesEventsRequest{
		GreaterThanEventID: a.lastRegistrationEntryEventID,
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
		a.lastRegistrationEntryEventID++

		entry, err := api.RegistrationEntryToProto(commonEntry)
		if err != nil {
			a.cache.RemoveEntry(entryID)
			continue
		}

		a.cache.UpdateEntry(entry)
	}

	return nil
}

func (a *AuthorizedEntryFetcherWithEventsBasedCache) updateAttestedNodesCache(ctx context.Context) error {
	req := &datastore.ListAttestedNodesEventsRequest{
		GreaterThanEventID: a.lastAttestedNodeEventID,
	}
	resp, err := a.ds.ListAttestedNodesEvents(ctx, req)
	if err != nil {
		return err
	}

	for _, spiffeID := range resp.SpiffeIDs {
		node, err := a.ds.FetchAttestedNode(ctx, spiffeID)
		if err != nil {
			return err
		}
		a.lastAttestedNodeEventID++

		if node == nil {
			a.cache.RemoveAgent(spiffeID)
			continue
		}

		agentExpiresAt := time.Unix(node.CertNotAfter, 0)
		if agentExpiresAt.Before(time.Now()) {
			a.cache.RemoveAgent(spiffeID)
			continue
		}

		a.cache.UpdateAgent(node.SpiffeId, agentExpiresAt, api.ProtoFromSelectors(node.Selectors))
	}

	return nil
}

func buildCache(ctx context.Context, ds datastore.DataStore) (*authorizedentries.Cache, error) {
	cache := authorizedentries.NewCache()

	if err := buildRegistrationEntriesCache(ctx, ds, cache); err != nil {
		return nil, err
	}

	if err := buildAttestedNodesCache(ctx, ds, cache); err != nil {
		return nil, err
	}

	return cache, nil
}

// Fetches all registration entries and adds them to the cache
func buildRegistrationEntriesCache(ctx context.Context, ds datastore.DataStore, cache *authorizedentries.Cache) error {
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
func buildAttestedNodesCache(ctx context.Context, ds datastore.DataStore, cache *authorizedentries.Cache) error {
	resp, err := ds.ListAttestedNodes(ctx, &datastore.ListAttestedNodesRequest{
		FetchSelectors: true,
	})
	if err != nil {
		return err
	}

	for _, node := range resp.Nodes {
		agentExpiresAt := time.Unix(node.CertNotAfter, 0)
		if agentExpiresAt.Before(time.Now()) {
			continue
		}
		cache.UpdateAgent(node.SpiffeId, agentExpiresAt, api.ProtoFromSelectors(node.Selectors))
	}

	return nil
}
