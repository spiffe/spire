package endpoints

import (
	"context"
	"errors"
	"fmt"
	"sync"
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

const buildCachePageSize = 10000

type AuthorizedEntryFetcherWithEventsBasedCache struct {
	mu                            sync.RWMutex
	cache                         *authorizedentries.Cache
	clk                           clock.Clock
	log                           logrus.FieldLogger
	ds                            datastore.DataStore
	cacheReloadInterval           time.Duration
	pruneEventsOlderThan          time.Duration
	lastRegistrationEntryEventID  uint
	lastAttestedNodeEventID       uint
	missedRegistrationEntryEvents map[uint]time.Time
	missedAttestedNodeEvents      map[uint]time.Time
}

func NewAuthorizedEntryFetcherWithEventsBasedCache(ctx context.Context, log logrus.FieldLogger, clk clock.Clock, ds datastore.DataStore, cacheReloadInterval, pruneEventsOlderThan time.Duration) (*AuthorizedEntryFetcherWithEventsBasedCache, error) {
	log.Info("Building event-based in-memory entry cache")
	cache, lastRegistrationEntryEventID, missedRegistrationEntryEvents, missedAttestedNodeEvents, lastAttestedNodeEventID, err := buildCache(ctx, ds, clk)
	if err != nil {
		return nil, err
	}
	log.Info("Completed building event-based in-memory entry cache")

	return &AuthorizedEntryFetcherWithEventsBasedCache{
		cache:                         cache,
		clk:                           clk,
		log:                           log,
		ds:                            ds,
		cacheReloadInterval:           cacheReloadInterval,
		pruneEventsOlderThan:          pruneEventsOlderThan,
		lastRegistrationEntryEventID:  lastRegistrationEntryEventID,
		lastAttestedNodeEventID:       lastAttestedNodeEventID,
		missedRegistrationEntryEvents: missedRegistrationEntryEvents,
		missedAttestedNodeEvents:      missedAttestedNodeEvents,
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
	pruneRegistrationEntriesEventsErr := a.ds.PruneRegistrationEntriesEvents(ctx, olderThan)
	pruneAttestedNodesEventsErr := a.ds.PruneAttestedNodesEvents(ctx, olderThan)
	a.pruneMissedRegistrationEntriesEvents()

	return errors.Join(pruneRegistrationEntriesEventsErr, pruneAttestedNodesEventsErr)
}

func (a *AuthorizedEntryFetcherWithEventsBasedCache) pruneMissedRegistrationEntriesEvents() {
	a.mu.Lock()
	defer a.mu.Unlock()

	for eventID, eventTime := range a.missedRegistrationEntryEvents {
		if time.Since(eventTime) > a.pruneEventsOlderThan {
			delete(a.missedRegistrationEntryEvents, eventID)
		}
	}
}

func (a *AuthorizedEntryFetcherWithEventsBasedCache) updateCache(ctx context.Context) error {
	updateRegistrationEntriesCacheErr := a.updateRegistrationEntriesCache(ctx)
	updateAttestedNodesCacheErr := a.updateAttestedNodesCache(ctx)

	return errors.Join(updateRegistrationEntriesCacheErr, updateAttestedNodesCacheErr)
}

// updateRegistrationEntriesCache Fetches all the events since the last time this function was running and updates
// the cache with all the changes.
func (a *AuthorizedEntryFetcherWithEventsBasedCache) updateRegistrationEntriesCache(ctx context.Context) error {
	// Pocess events skipped over previously
	a.replayMissedRegistrationEntryEvents(ctx)

	req := &datastore.ListRegistrationEntriesEventsRequest{
		GreaterThanEventID: a.lastRegistrationEntryEventID,
	}
	resp, err := a.ds.ListRegistrationEntriesEvents(ctx, req)
	if err != nil {
		return err
	}

	seenMap := map[string]struct{}{}
	for _, event := range resp.Events {
		// If there is a gap in the event stream, log the missed events for later processing
		if event.EventID != a.lastRegistrationEntryEventID+1 && a.lastRegistrationEntryEventID != 0 {
			for i := a.lastRegistrationEntryEventID + 1; i < event.EventID; i++ {
				a.mu.Lock()
				a.missedRegistrationEntryEvents[i] = a.clk.Now()
				a.mu.Unlock()
			}
		}

		// Skip fetching entries we've already fetched this call
		if _, seen := seenMap[event.EntryID]; seen {
			a.lastRegistrationEntryEventID = event.EventID
			continue
		}
		seenMap[event.EntryID] = struct{}{}

		// Update the cache
		if err := a.updateRegistrationEntryCache(ctx, event.EntryID); err != nil {
			return err
		}
		a.lastRegistrationEntryEventID = event.EventID
	}

	return nil
}

// replayMissedRegistrationEntryEvents Processes events that have been skipped over. Events can come out of order from
// SQL. This function processes events that came in later than expected.
func (a *AuthorizedEntryFetcherWithEventsBasedCache) replayMissedRegistrationEntryEvents(ctx context.Context) {
	a.mu.Lock()
	defer a.mu.Unlock()

	for eventID := range a.missedRegistrationEntryEvents {
		log := a.log.WithField("eventID", eventID)
		event, err := a.ds.FetchRegistrationEntryEvent(ctx, eventID)
		if err != nil {
			log.WithError(err).Error("Failed to fetch info about missed event")
			continue
		}
		if err := a.updateRegistrationEntryCache(ctx, event.EntryID); err != nil {
			log.WithError(err).Error("Failed to process missed event")
			continue
		}
		delete(a.missedRegistrationEntryEvents, eventID)
	}
}

// updateRegistrationEntryCache update/deletes/creates an individual registration entry in the cache.
func (a *AuthorizedEntryFetcherWithEventsBasedCache) updateRegistrationEntryCache(ctx context.Context, entryID string) error {
	commonEntry, err := a.ds.FetchRegistrationEntry(ctx, entryID)
	if err != nil {
		return err
	}

	entry, err := api.RegistrationEntryToProto(commonEntry)
	if err != nil {
		a.cache.RemoveEntry(entryID)
		return nil
	}

	a.cache.UpdateEntry(entry)
	return nil
}

// updateAttestedNodesCache Fetches all the events since the last time this function was running and updates
// the cache with all the changes.
func (a *AuthorizedEntryFetcherWithEventsBasedCache) updateAttestedNodesCache(ctx context.Context) error {
	// Pocess events skipped over previously
	a.replayMissedAttestedNodeEvents(ctx)

	req := &datastore.ListAttestedNodesEventsRequest{
		GreaterThanEventID: a.lastAttestedNodeEventID,
	}
	resp, err := a.ds.ListAttestedNodesEvents(ctx, req)
	if err != nil {
		return err
	}

	seenMap := map[string]struct{}{}
	for _, event := range resp.Events {
		// If there is a gap in the event stream, log the missed events for later processing
		if event.EventID != a.lastAttestedNodeEventID+1 && a.lastAttestedNodeEventID != 0 {
			for i := a.lastAttestedNodeEventID + 1; i < event.EventID; i++ {
				a.mu.Lock()
				a.missedAttestedNodeEvents[i] = a.clk.Now()
				a.mu.Unlock()
			}
		}

		// Skip fetching entries we've already fetched this call
		if _, seen := seenMap[event.SpiffeID]; seen {
			a.lastAttestedNodeEventID = event.EventID
			continue
		}
		seenMap[event.SpiffeID] = struct{}{}

		// Update the cache
		if err := a.updateAttestedNodeCache(ctx, event.SpiffeID); err != nil {
			return err
		}
		a.lastAttestedNodeEventID = event.EventID
	}

	return nil
}

// replayMissedAttestedNodeEvents Processes events that have been skipped over. Events can come out of order from
// SQL. This function processes events that came in later than expected.
func (a *AuthorizedEntryFetcherWithEventsBasedCache) replayMissedAttestedNodeEvents(ctx context.Context) {
	a.mu.Lock()
	defer a.mu.Unlock()

	for eventID := range a.missedAttestedNodeEvents {
		log := a.log.WithField("eventID", eventID)
		event, err := a.ds.FetchAttestedNodeEvent(ctx, eventID)
		if err != nil {
			log.WithError(err).Error("Failed to fetch info about missed Attested Node event")
			continue
		}
		if err := a.updateAttestedNodeCache(ctx, event.SpiffeID); err != nil {
			log.WithError(err).Error("Failed to process missed Attested Node event")
			continue
		}
		delete(a.missedAttestedNodeEvents, eventID)
	}
}

// updateAttestedNodeCache update/deletes/creates an individual attested node in the cache.
func (a *AuthorizedEntryFetcherWithEventsBasedCache) updateAttestedNodeCache(ctx context.Context, spiffeID string) error {
	node, err := a.ds.FetchAttestedNode(ctx, spiffeID)
	if err != nil {
		return err
	}

	// Node was deleted
	if node == nil {
		a.cache.RemoveAgent(spiffeID)
		return nil
	}

	selectors, err := a.ds.GetNodeSelectors(ctx, spiffeID, datastore.RequireCurrent)
	if err != nil {
		return err
	}
	node.Selectors = selectors

	agentExpiresAt := time.Unix(node.CertNotAfter, 0)
	a.cache.UpdateAgent(node.SpiffeId, agentExpiresAt, api.ProtoFromSelectors(node.Selectors))

	return nil
}

func buildCache(ctx context.Context, ds datastore.DataStore, clk clock.Clock) (*authorizedentries.Cache, uint, map[uint]time.Time, map[uint]time.Time, uint, error) {
	cache := authorizedentries.NewCache(clk)

	lastRegistrationEntryEventID, missedRegistrationEntryEvents, err := buildRegistrationEntriesCache(ctx, ds, clk, cache, buildCachePageSize)
	if err != nil {
		return nil, 0, nil, nil, 0, err
	}

	lastAttestedNodeEventID, missedAttestedNodeEvents, err := buildAttestedNodesCache(ctx, ds, clk, cache)
	if err != nil {
		return nil, 0, nil, nil, 0, err
	}

	return cache, lastRegistrationEntryEventID, missedRegistrationEntryEvents, missedAttestedNodeEvents, lastAttestedNodeEventID, nil
}

// buildRegistrationEntriesCache Fetches all registration entries and adds them to the cache
func buildRegistrationEntriesCache(ctx context.Context, ds datastore.DataStore, clk clock.Clock, cache *authorizedentries.Cache, pageSize int32) (uint, map[uint]time.Time, error) {
	// Gather any events that may have been skipped during restart
	var lastEventID uint
	missedRegistrationEntryEvents := make(map[uint]time.Time)
	resp, err := ds.ListRegistrationEntriesEvents(ctx, &datastore.ListRegistrationEntriesEventsRequest{})
	if err != nil {
		return 0, nil, err
	}
	for _, event := range resp.Events {
		if event.EventID != lastEventID+1 && lastEventID != 0 {
			for i := lastEventID + 1; i < event.EventID; i++ {
				missedRegistrationEntryEvents[i] = clk.Now()
			}
		}
		lastEventID = event.EventID
	}

	// Build the cache
	var token string
	for {
		resp, err := ds.ListRegistrationEntries(ctx, &datastore.ListRegistrationEntriesRequest{
			DataConsistency: datastore.RequireCurrent, // preliminary loading should not be done via read-replicas
			Pagination: &datastore.Pagination{
				Token:    token,
				PageSize: pageSize,
			},
		})
		if err != nil {
			return 0, nil, fmt.Errorf("failed to list registration entries: %w", err)
		}

		token = resp.Pagination.Token
		if token == "" {
			break
		}

		entries, err := api.RegistrationEntriesToProto(resp.Entries)
		if err != nil {
			return 0, nil, fmt.Errorf("failed to convert registration entries: %w", err)
		}

		for _, entry := range entries {
			cache.UpdateEntry(entry)
		}
	}

	return lastEventID, missedRegistrationEntryEvents, nil
}

// buildAttestedNodesCache Fetches all attested nodes and adds the unexpired ones to the cache
func buildAttestedNodesCache(ctx context.Context, ds datastore.DataStore, clk clock.Clock, cache *authorizedentries.Cache) (uint, map[uint]time.Time, error) {
	// Gather any events that may have been skipped during restart
	var lastEventID uint
	missedAttestedNodeEvents := make(map[uint]time.Time)
	resp, err := ds.ListAttestedNodesEvents(ctx, &datastore.ListAttestedNodesEventsRequest{})
	if err != nil {
		return 0, nil, err
	}
	for _, event := range resp.Events {
		if event.EventID != lastEventID+1 && lastEventID != 0 {
			for i := lastEventID + 1; i < event.EventID; i++ {
				missedAttestedNodeEvents[i] = clk.Now()
			}
		}
		lastEventID = event.EventID
	}

	// Build the cache
	nodesResp, err := ds.ListAttestedNodes(ctx, &datastore.ListAttestedNodesRequest{
		FetchSelectors: true,
	})
	if err != nil {
		return 0, nil, fmt.Errorf("failed to list attested nodes: %w", err)
	}

	for _, node := range nodesResp.Nodes {
		agentExpiresAt := time.Unix(node.CertNotAfter, 0)
		if agentExpiresAt.Before(clk.Now()) {
			continue
		}
		cache.UpdateAgent(node.SpiffeId, agentExpiresAt, api.ProtoFromSelectors(node.Selectors))
	}

	return lastEventID, missedAttestedNodeEvents, nil
}
