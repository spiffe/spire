package endpoints

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/pkg/server/authorizedentries"
	"github.com/spiffe/spire/pkg/server/datastore"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type registrationEntries struct {
	cache *authorizedentries.Cache
	clk   clock.Clock
	ds    datastore.DataStore
	log   logrus.FieldLogger
	mu    sync.RWMutex

	lastEventID        uint
	missedEvents       map[uint]time.Time
	receivedFirstEvent bool
}

// buildRegistrationEntriesCache Fetches all registration entries and adds them to the cache
func buildRegistrationEntriesCache(ctx context.Context, log logrus.FieldLogger, ds datastore.DataStore, clk clock.Clock, cache *authorizedentries.Cache, pageSize int32) (*registrationEntries, error) {
	resp, err := ds.ListRegistrationEntriesEvents(ctx, &datastore.ListRegistrationEntriesEventsRequest{})
	if err != nil {
		return nil, err
	}

	// Gather any events that may have been skipped during restart
	var lastEventID uint
	var receivedFirstEvent bool
	missedEvents := make(map[uint]time.Time)
	for _, event := range resp.Events {
		if receivedFirstEvent && event.EventID != lastEventID+1 {
			for i := lastEventID + 1; i < event.EventID; i++ {
				missedEvents[i] = clk.Now()
			}
		}
		lastEventID = event.EventID
		receivedFirstEvent = true
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
		cache:              cache,
		clk:                clk,
		ds:                 ds,
		log:                log,
		lastEventID:        lastEventID,
		missedEvents:       missedEvents,
		receivedFirstEvent: receivedFirstEvent,
	}, nil
}

// updateCache Fetches all the events since the last time this function was running and updates
// the cache with all the changes.
func (a *registrationEntries) updateCache(ctx context.Context) error {
	// Process events skipped over previously
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
		// the longer running transaction will be skipped over
		if a.receivedFirstEvent && event.EventID != a.lastEventID+1 {
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
		a.lastEventID = event.EventID
		a.receivedFirstEvent = true
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
			log.Debug("Event not yet populated in database")
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
func (a *registrationEntries) pruneMissedEvents(sqlTransactionTimeout time.Duration) {
	a.mu.Lock()
	defer a.mu.Unlock()

	for eventID, eventTime := range a.missedEvents {
		if a.clk.Now().Sub(eventTime) > sqlTransactionTimeout {
			delete(a.missedEvents, eventID)
		}
	}
}
