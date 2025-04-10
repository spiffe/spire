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
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type registrationEntries struct {
	cache   *authorizedentries.Cache
	clk     clock.Clock
	ds      datastore.DataStore
	log     logrus.FieldLogger
	metrics telemetry.Metrics

	eventsBeforeFirst map[uint]struct{}

	firstEvent     uint
	firstEventTime time.Time
	lastEvent      uint

	eventTracker          *eventTracker
	sqlTransactionTimeout time.Duration
	pageSize              int32

	fetchEntries map[string]struct{}

	// metrics change detection
	skippedEntryEvents int
	lastCacheStats     authorizedentries.CacheStats
}

func (a *registrationEntries) captureChangedEntries(ctx context.Context) error {
	if err := a.searchBeforeFirstEvent(ctx); err != nil {
		return err
	}
	a.selectPolledEvents(ctx)
	if err := a.scanForNewEvents(ctx); err != nil {
		return err
	}

	return nil
}

func (a *registrationEntries) searchBeforeFirstEvent(ctx context.Context) error {
	// First event detected, and startup was less than a transaction timout away.
	if !a.firstEventTime.IsZero() && a.clk.Now().Sub(a.firstEventTime) <= a.sqlTransactionTimeout {
		resp, err := a.ds.ListRegistrationEntryEvents(ctx, &datastore.ListRegistrationEntryEventsRequest{
			LessThanEventID: a.firstEvent,
		})
		if err != nil {
			return err
		}
		for _, event := range resp.Events {
			// if we have seen it before, don't reload it.
			if _, seen := a.eventsBeforeFirst[event.EventID]; !seen {
				a.fetchEntries[event.EntryID] = struct{}{}
				a.eventsBeforeFirst[event.EventID] = struct{}{}
			}
		}
		return nil
	}

	// zero out unused event tracker
	if len(a.eventsBeforeFirst) != 0 {
		a.eventsBeforeFirst = make(map[uint]struct{})
	}

	return nil
}

func (a *registrationEntries) selectPolledEvents(ctx context.Context) {
	// check if the polled events have appeared out-of-order
	selectedEvents := a.eventTracker.SelectEvents()
	for _, eventID := range selectedEvents {
		log := a.log.WithField(telemetry.EventID, eventID)
		event, err := a.ds.FetchRegistrationEntryEvent(ctx, eventID)

		switch status.Code(err) {
		case codes.OK:
		case codes.NotFound:
			continue
		default:
			log.WithError(err).Errorf("Failed to fetch info about skipped event %d", eventID)
			continue
		}

		a.fetchEntries[event.EntryID] = struct{}{}
		a.eventTracker.StopTracking(eventID)
	}
	a.eventTracker.FreeEvents(selectedEvents)
}

func (a *registrationEntries) scanForNewEvents(ctx context.Context) error {
	resp, err := a.ds.ListRegistrationEntryEvents(ctx, &datastore.ListRegistrationEntryEventsRequest{
		DataConsistency:    datastore.TolerateStale,
		GreaterThanEventID: a.lastEvent,
	})
	if err != nil {
		return err
	}

	for _, event := range resp.Events {
		// event time determines if we have seen the first event.
		if a.firstEventTime.IsZero() {
			a.firstEvent = event.EventID
			a.lastEvent = event.EventID
			a.fetchEntries[event.EntryID] = struct{}{}
			a.firstEventTime = a.clk.Now()
			continue
		}

		// track any skipped event ids, should they appear later.
		for skipped := a.lastEvent + 1; skipped < event.EventID; skipped++ {
			a.eventTracker.StartTracking(skipped)
		}

		// every event adds its entry to the entry fetch list.
		a.fetchEntries[event.EntryID] = struct{}{}
		a.lastEvent = event.EventID
	}
	return nil
}

func (a *registrationEntries) loadCache(ctx context.Context) error {
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
			a.cache.UpdateEntry(entry)
		}
	}
	return nil
}

// buildRegistrationEntriesCache Fetches all registration entries and adds them to the cache
func buildRegistrationEntriesCache(ctx context.Context, log logrus.FieldLogger, metrics telemetry.Metrics, ds datastore.DataStore, clk clock.Clock, cache *authorizedentries.Cache, pageSize int32, cacheReloadInterval, sqlTransactionTimeout time.Duration) (*registrationEntries, error) {
	pollPeriods := PollPeriods(cacheReloadInterval, sqlTransactionTimeout)

	registrationEntries := &registrationEntries{
		cache:                 cache,
		clk:                   clk,
		ds:                    ds,
		log:                   log,
		metrics:               metrics,
		sqlTransactionTimeout: sqlTransactionTimeout,
		pageSize:              pageSize,

		eventsBeforeFirst: make(map[uint]struct{}),
		fetchEntries:      make(map[string]struct{}),

		eventTracker: NewEventTracker(pollPeriods),

		skippedEntryEvents: -1,
		lastCacheStats: authorizedentries.CacheStats{
			AliasesByEntryID:  -1,
			AliasesBySelector: -1,
			EntriesByEntryID:  -1,
			EntriesByParentID: -1,
		},
	}

	if err := registrationEntries.captureChangedEntries(ctx); err != nil {
		return nil, err
	}

	if err := registrationEntries.loadCache(ctx); err != nil {
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

func (a *registrationEntries) emitMetrics() {
	if a.skippedEntryEvents != a.eventTracker.EventCount() {
		a.skippedEntryEvents = a.eventTracker.EventCount()
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
	if a.lastCacheStats.EntriesByParentID != cacheStats.EntriesByParentID {
		a.lastCacheStats.EntriesByParentID = cacheStats.EntriesByParentID
		server_telemetry.SetEntriesByParentIDCacheCountGauge(a.metrics, a.lastCacheStats.EntriesByParentID)
	}
}
