package endpoints

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/telemetry"
	server_telemetry "github.com/spiffe/spire/pkg/common/telemetry/server"
	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/pkg/server/authorizedentries"
	"github.com/spiffe/spire/pkg/server/datastore"
)

type registrationEntries struct {
	cache   *authorizedentries.Cache
	clk     clock.Clock
	ds      datastore.DataStore
	log     logrus.FieldLogger
	metrics telemetry.Metrics

	eventTimeout time.Duration
	pageSize     int32

	fetchEntries map[string]struct{}

	// metrics change detection
	pendingEntryEvents int
	skippedEntryEvents int
	lastCacheStats     authorizedentries.CacheStats
}

func (a *registrationEntries) captureChangedEntries(ctx context.Context) error {
	resp, err := a.ds.FetchRegistrationEntryChanges(ctx, &datastore.FetchRegistrationEntryChangesRequest{
		EventTimeout: a.eventTimeout,
	})
	if err != nil {
		return err
	}

	for _, entryID := range resp.EntryIDs {
		a.fetchEntries[entryID] = struct{}{}
	}
	a.pendingEntryEvents = int(resp.PendingEvents)
	return nil
}

func (a *registrationEntries) loadCache(ctx context.Context, cache *authorizedentries.Cache) error {
	// Build the cache
	var token string
	for {
		resp, err := a.ds.ListRegistrationEntries(ctx, &datastore.ListRegistrationEntriesRequest{
			DataConsistency: datastore.RequireCurrent, // preliminary loading should not be done via read-replicas
			Pagination: &datastore.Pagination{
				Token:    token,
				PageSize: a.pageSize,
			},
		})
		if err != nil {
			return fmt.Errorf("failed to list registration entries: %w", err)
		}

		token = resp.Pagination.Token
		if token == "" {
			break
		}

		entries, err := api.RegistrationEntriesToProto(resp.Entries)
		if err != nil {
			return fmt.Errorf("failed to convert registration entries: %w", err)
		}

		for _, entry := range entries {
			cache.UpdateEntry(entry)
		}
	}
	return nil
}

// buildRegistrationEntriesCache Fetches all registration entries and adds them to the cache
func buildRegistrationEntriesCache(ctx context.Context, log logrus.FieldLogger, metrics telemetry.Metrics, ds datastore.DataStore, clk clock.Clock, cache *authorizedentries.Cache, pageSize int32, eventTimeout time.Duration) (*registrationEntries, error) {
	registrationEntries := &registrationEntries{
		cache:        cache,
		clk:          clk,
		ds:           ds,
		log:          log,
		metrics:      metrics,
		eventTimeout: eventTimeout,
		pageSize:     pageSize,

		fetchEntries: make(map[string]struct{}),

		skippedEntryEvents: -1,
		lastCacheStats: authorizedentries.CacheStats{
			AliasesByEntryID:  -1,
			AliasesBySelector: -1,
			EntriesByEntryID:  -1,
		},
	}

	if err := registrationEntries.captureChangedEntries(ctx); err != nil {
		return nil, err
	}

	if err := registrationEntries.loadCache(ctx, cache); err != nil {
		return nil, err
	}

	registrationEntries.emitMetrics()

	return registrationEntries, nil
}

// updateCache Fetches all the events since the last time this function was running and updates
// the cache with all the changes.
func (a *registrationEntries) updateCache(ctx context.Context) error {
	if err := a.captureChangedEntries(ctx); err != nil {
		return err
	}
	if err := a.updateCachedEntries(ctx); err != nil {
		return err
	}
	a.emitMetrics()

	return nil
}

// updateCacheEntry update/deletes/creates an individual registration entry in the cache.
func (a *registrationEntries) updateCachedEntries(ctx context.Context) error {
	entryIds := slices.Collect(maps.Keys(a.fetchEntries))
	for pageStart := 0; pageStart < len(entryIds); pageStart += int(a.pageSize) {
		fetchEntries := a.fetchEntriesPage(entryIds, pageStart)
		commonEntries, err := a.ds.FetchRegistrationEntries(ctx, fetchEntries)
		if err != nil {
			return err
		}

		for _, entryId := range fetchEntries {
			commonEntry, ok := commonEntries[entryId]
			if !ok {
				a.cache.RemoveEntry(entryId)
				delete(a.fetchEntries, entryId)
				continue
			}

			entry, err := api.RegistrationEntryToProto(commonEntry)
			if err != nil {
				a.cache.RemoveEntry(entryId)
				delete(a.fetchEntries, entryId)
				a.log.WithField(telemetry.RegistrationID, entryId).Warn("Removed malformed registration entry from cache")
				continue
			}

			a.cache.UpdateEntry(entry)
			delete(a.fetchEntries, entryId)
		}
	}

	return nil
}

// fetchEntriesPage gets the range for the page starting at pageStart
func (a *registrationEntries) fetchEntriesPage(entryIds []string, pageStart int) []string {
	pageEnd := min(len(entryIds), pageStart+int(a.pageSize))
	return entryIds[pageStart:pageEnd]
}

func (a *registrationEntries) swapCache(cache *authorizedentries.Cache) {
	a.cache = cache
}

func (a *registrationEntries) emitMetrics() {
	if a.skippedEntryEvents != a.pendingEntryEvents {
		a.skippedEntryEvents = a.pendingEntryEvents
		server_telemetry.SetSkippedEntryEventIDsCacheCountGauge(a.metrics, a.skippedEntryEvents)
	}

	cacheStats := a.cache.Stats()
	if a.lastCacheStats.AliasesByEntryID != cacheStats.AliasesByEntryID {
		a.lastCacheStats.AliasesByEntryID = cacheStats.AliasesByEntryID
		server_telemetry.SetNodeAliasesByEntryIDCacheCountGauge(a.metrics, a.lastCacheStats.AliasesByEntryID)
	}
	if a.lastCacheStats.AliasesBySelector != cacheStats.AliasesBySelector {
		a.lastCacheStats.AliasesBySelector = cacheStats.AliasesBySelector
		server_telemetry.SetNodeAliasesBySelectorCacheCountGauge(a.metrics, a.lastCacheStats.AliasesBySelector)
	}
	if a.lastCacheStats.EntriesByEntryID != cacheStats.EntriesByEntryID {
		a.lastCacheStats.EntriesByEntryID = cacheStats.EntriesByEntryID
		server_telemetry.SetEntriesByEntryIDCacheCountGauge(a.metrics, a.lastCacheStats.EntriesByEntryID)
	}
}
