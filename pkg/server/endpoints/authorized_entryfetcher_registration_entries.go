package endpoints

import (
	"context"
	"fmt"
	"sync"
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
	mu      sync.RWMutex

	firstEventID            uint
	firstEventTime          time.Time
	lastEventID             uint
	missedEvents            map[uint]time.Time
	seenMissedStartupEvents map[uint]struct{}
	sqlTransactionTimeout   time.Duration
}

// buildRegistrationEntriesCache Fetches all registration entries and adds them to the cache
func buildRegistrationEntriesCache(ctx context.Context, log logrus.FieldLogger, metrics telemetry.Metrics, ds datastore.DataStore, clk clock.Clock, cache *authorizedentries.Cache, pageSize int32, sqlTransactionTimeout time.Duration) (*registrationEntries, error) {
	resp, err := ds.ListRegistrationEntriesEvents(ctx, &datastore.ListRegistrationEntriesEventsRequest{})
	if err != nil {
		return nil, err
	}

	// Gather any events that may have been skipped during restart
	var firstEventID uint
	var firstEventTime time.Time
	var lastEventID uint
	missedEvents := make(map[uint]time.Time)
	for _, event := range resp.Events {
		now := clk.Now()
		if firstEventTime.IsZero() {
			firstEventID = event.EventID
			firstEventTime = now
		} else {
			// After getting the first event, search for any gaps in the event stream, from the first event to the last event.
			// During each cache refresh cycle, we will check if any of these missed events get populated.
			for i := lastEventID + 1; i < event.EventID; i++ {
				missedEvents[i] = clk.Now()
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
			return nil, fmt.Errorf("failed to list registration entries: %w", err)
		}

		token = resp.Pagination.Token
		if token == "" {
			break
		}

		entries, err := api.RegistrationEntriesToProto(resp.Entries)
		if err != nil {
			return nil, fmt.Errorf("failed to convert registration entries: %w", err)
		}

		for _, entry := range entries {
			cache.UpdateEntry(entry)
		}
	}

	return &registrationEntries{
		cache:                   cache,
		clk:                     clk,
		ds:                      ds,
		firstEventID:            firstEventID,
		firstEventTime:          firstEventTime,
		log:                     log,
		metrics:                 metrics,
		lastEventID:             lastEventID,
		missedEvents:            missedEvents,
		seenMissedStartupEvents: make(map[uint]struct{}),
		sqlTransactionTimeout:   sqlTransactionTimeout,
	}, nil
}

// updateCache Fetches all the events since the last time this function was running and updates
// the cache with all the changes.
func (a *registrationEntries) updateCache(ctx context.Context) error {
	// Process events skipped over previously
	if err := a.missedStartupEvents(ctx); err != nil {
		a.log.WithError(err).Error("Unable to process missed startup events")
	}
	a.replayMissedEvents(ctx)

	req := &datastore.ListRegistrationEntriesEventsRequest{
		GreaterThanEventID: a.lastEventID,
	}
	resp, err := a.ds.ListRegistrationEntriesEvents(ctx, req)
	if err != nil {
		return err
	}

	seenMap := map[string]struct{}{}
	for _, event := range resp.Events {
		// If there is a gap in the event stream, log the missed events for later processing.
		// For example if the current event ID is 6 and the previous one was 3, events 4 and 5
		// were skipped over and need to be queued in case they show up later.
		// This can happen when a long running transaction allocates an event ID but a shorter transaction
		// comes in after, allocates and commits the ID first. If a read comes in at this moment, the event id for
		// the longer running transaction will be skipped over.
		if !a.firstEventTime.IsZero() {
			for i := a.lastEventID + 1; i < event.EventID; i++ {
				a.log.WithField(telemetry.EventID, i).Info("Detected skipped registration entry event")
				a.mu.Lock()
				a.missedEvents[i] = a.clk.Now()
				a.mu.Unlock()
			}
		}

		// Skip fetching entries we've already fetched this call
		if _, seen := seenMap[event.EntryID]; seen {
			a.lastEventID = event.EventID
			continue
		}
		seenMap[event.EntryID] = struct{}{}

		// Update the cache
		if err := a.updateCacheEntry(ctx, event.EntryID); err != nil {
			return err
		}

		if a.firstEventTime.IsZero() {
			a.firstEventID = event.EventID
			a.firstEventTime = a.clk.Now()
		}
		a.lastEventID = event.EventID
	}

	// These two should be the same value but it's valuable to have them both be emitted for incident triage.
	server_telemetry.SetNodeAliasesByEntryIDCacheCountGauge(a.metrics, a.cache.Stats().AliasesByEntryID)
	server_telemetry.SetNodeAliasesBySelectorCacheCountGauge(a.metrics, a.cache.Stats().AliasesBySelector)

	// These two should be the same value but it's valuable to have them both be emitted for incident triage.
	server_telemetry.SetEntriesByEntryIDCacheCountGauge(a.metrics, a.cache.Stats().EntriesByEntryID)
	server_telemetry.SetEntriesByParentIDCacheCountGauge(a.metrics, a.cache.Stats().EntriesByParentID)

	return nil
}

// missedStartupEvents will check for any events come in with an ID less than the first event ID we receive.
// For example if the first event ID we receive is 3, this function will check for any IDs less than that.
// If event ID 2 comes in later on, due to a long running transaction, this function will update the cache
// with the information from this event. This function will run until time equal to sqlTransactionTimeout has elapsed after startup.
func (a *registrationEntries) missedStartupEvents(ctx context.Context) error {
	if a.firstEventTime.IsZero() || a.clk.Now().Sub(a.firstEventTime) > a.sqlTransactionTimeout {
		return nil
	}

	req := &datastore.ListRegistrationEntriesEventsRequest{
		LessThanEventID: a.firstEventID,
	}
	resp, err := a.ds.ListRegistrationEntriesEvents(ctx, req)
	if err != nil {
		return err
	}

	for _, event := range resp.Events {
		if _, seen := a.seenMissedStartupEvents[event.EventID]; !seen {
			if err := a.updateCacheEntry(ctx, event.EntryID); err != nil {
				a.log.WithError(err).Error("Failed to process missed startup event")
				continue
			}
			a.seenMissedStartupEvents[event.EventID] = struct{}{}
		}
	}

	return nil
}

// replayMissedEvents Processes events that have been skipped over. Events can come out of order from
// SQL. This function processes events that came in later than expected.
func (a *registrationEntries) replayMissedEvents(ctx context.Context) {
	a.mu.Lock()
	defer a.mu.Unlock()

	for eventID := range a.missedEvents {
		log := a.log.WithField(telemetry.EventID, eventID)

		event, err := a.ds.FetchRegistrationEntryEvent(ctx, eventID)
		switch status.Code(err) {
		case codes.OK:
		case codes.NotFound:
			continue
		default:
			log.WithError(err).Error("Failed to fetch info about missed event")
			continue
		}

		if err := a.updateCacheEntry(ctx, event.EntryID); err != nil {
			log.WithError(err).Error("Failed to process missed event")
			continue
		}

		delete(a.missedEvents, eventID)
	}
	server_telemetry.SetSkippedEntryEventIDsCacheCountGauge(a.metrics, len(a.missedEvents))
}

// updateCacheEntry update/deletes/creates an individual registration entry in the cache.
func (a *registrationEntries) updateCacheEntry(ctx context.Context, entryID string) error {
	commonEntry, err := a.ds.FetchRegistrationEntry(ctx, entryID)
	if err != nil {
		return err
	}

	if commonEntry == nil {
		a.cache.RemoveEntry(entryID)
		return nil
	}

	entry, err := api.RegistrationEntryToProto(commonEntry)
	if err != nil {
		a.cache.RemoveEntry(entryID)
		a.log.WithField(telemetry.RegistrationID, entryID).Warn("Removed malformed registration entry from cache")
		return nil
	}

	a.cache.UpdateEntry(entry)
	return nil
}

// prunedMissedEvents delete missed events that are older than the configured SQL transaction timeout time.
func (a *registrationEntries) pruneMissedEvents() {
	a.mu.Lock()
	defer a.mu.Unlock()

	for eventID, eventTime := range a.missedEvents {
		if a.clk.Now().Sub(eventTime) > a.sqlTransactionTimeout {
			delete(a.missedEvents, eventID)
		}
	}
}
