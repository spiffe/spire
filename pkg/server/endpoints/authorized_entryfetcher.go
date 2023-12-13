package endpoints

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/pkg/server/authorizedentries"
	"github.com/spiffe/spire/pkg/server/datastore"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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
	log.Info("Building event-based in-memory entry cache")
	cache, lastRegistrationEntryEventID, lastAttestedNodeEventID, err := buildCache(ctx, ds, clk)
	if err != nil {
		return nil, err
	}
	log.Info("Completed building event-based in-memory entry cache")

	return &AuthorizedEntryFetcherWithEventsBasedCache{
		cache:                        cache,
		clk:                          clk,
		log:                          log,
		ds:                           ds,
		cacheReloadInterval:          cacheReloadInterval,
		pruneEventsOlderThan:         pruneEventsOlderThan,
		lastRegistrationEntryEventID: lastRegistrationEntryEventID,
		lastAttestedNodeEventID:      lastAttestedNodeEventID,
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

// PruneEventsTask start a ticker which prunes old events
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

	seenMap := map[string]struct{}{}
	for _, event := range resp.Events {
		// Skip fetching entries we've already fetched this call
		if _, seen := seenMap[event.EntryID]; seen {
			a.lastRegistrationEntryEventID = event.EventID
			continue
		}
		seenMap[event.EntryID] = struct{}{}

		commonEntry, err := a.ds.FetchRegistrationEntry(ctx, event.EntryID)
		if err != nil {
			return err
		}
		a.lastRegistrationEntryEventID = event.EventID

		entry, err := api.RegistrationEntryToProto(commonEntry)
		if err != nil {
			a.cache.RemoveEntry(event.EntryID)
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

	seenMap := map[string]struct{}{}
	for _, event := range resp.Events {
		// Skip fetching entries we've already fetched this call
		if _, seen := seenMap[event.SpiffeID]; seen {
			a.lastAttestedNodeEventID = event.EventID
			continue
		}
		seenMap[event.SpiffeID] = struct{}{}

		node, err := a.ds.FetchAttestedNode(ctx, event.SpiffeID)
		if err != nil {
			return err
		}
		a.lastAttestedNodeEventID = event.EventID

		if node == nil {
			a.cache.RemoveAgent(event.SpiffeID)
			continue
		}

		agentExpiresAt := time.Unix(node.CertNotAfter, 0)
		if agentExpiresAt.Before(a.clk.Now()) {
			a.cache.RemoveAgent(event.SpiffeID)
			continue
		}

		a.cache.UpdateAgent(node.SpiffeId, agentExpiresAt, api.ProtoFromSelectors(node.Selectors))
	}

	return nil
}

func buildCache(ctx context.Context, ds datastore.DataStore, clk clock.Clock) (*authorizedentries.Cache, uint, uint, error) {
	cache := authorizedentries.NewCache()

	lastRegistrationEntryEventID, err := buildRegistrationEntriesCache(ctx, ds, cache)
	if err != nil {
		return nil, 0, 0, err
	}

	lastAttestedNodeEventID, err := buildAttestedNodesCache(ctx, ds, clk, cache)
	if err != nil {
		return nil, 0, 0, err
	}

	return cache, lastRegistrationEntryEventID, lastAttestedNodeEventID, nil
}

// buildRegistrationEntriesCache Fetches all registration entries and adds them to the cache
func buildRegistrationEntriesCache(ctx context.Context, ds datastore.DataStore, cache *authorizedentries.Cache) (uint, error) {
	lastEventID, err := ds.GetLatestRegistrationEntryEventID(ctx)
	if err != nil && status.Code(err) != codes.NotFound {
		return 0, fmt.Errorf("failed to get latest registration entry event id: %w", err)
	}

	resp, err := ds.ListRegistrationEntries(ctx, &datastore.ListRegistrationEntriesRequest{
		DataConsistency: datastore.TolerateStale,
	})
	if err != nil {
		return 0, fmt.Errorf("failed to list registration entries: %w", err)
	}

	entries, err := api.RegistrationEntriesToProto(resp.Entries)
	if err != nil {
		return 0, fmt.Errorf("failed to convert registration entries: %w", err)
	}

	for _, entry := range entries {
		cache.UpdateEntry(entry)
	}

	return lastEventID, nil
}

// buildAttestedNodesCache Fetches all attested nodes and adds the unexpired ones to the cache
func buildAttestedNodesCache(ctx context.Context, ds datastore.DataStore, clk clock.Clock, cache *authorizedentries.Cache) (uint, error) {
	lastEventID, err := ds.GetLatestAttestedNodeEventID(ctx)
	if err != nil && status.Code(err) != codes.NotFound {
		return 0, fmt.Errorf("failed to get latest attested node event id: %w", err)
	}

	resp, err := ds.ListAttestedNodes(ctx, &datastore.ListAttestedNodesRequest{
		FetchSelectors: true,
	})
	if err != nil {
		return 0, fmt.Errorf("failed to list attested nodes: %w", err)
	}

	for _, node := range resp.Nodes {
		agentExpiresAt := time.Unix(node.CertNotAfter, 0)
		if agentExpiresAt.Before(clk.Now()) {
			continue
		}
		cache.UpdateAgent(node.SpiffeId, agentExpiresAt, api.ProtoFromSelectors(node.Selectors))
	}

	return lastEventID, nil
}
