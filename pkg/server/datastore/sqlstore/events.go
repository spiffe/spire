package sqlstore

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"math"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/jinzhu/gorm"
	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/pkg/server/datastore/sqlcommon"
)

const maxEventIDQuerySize = 500

type changeTracker struct {
	mu sync.Mutex

	firstEventID    uint
	startupDeadline time.Time
	startupSeen     map[uint]struct{}
	lastEventID     uint
	pending         map[uint]time.Time
}

type trackedEvent struct {
	id  uint
	key string
}

func (t *changeTracker) reset() {
	t.firstEventID = 0
	t.startupDeadline = time.Time{}
	t.startupSeen = nil
	t.lastEventID = 0
	t.pending = nil
}

func (ds *Plugin) FetchRegistrationEntryChanges(ctx context.Context, req *datastore.FetchRegistrationEntryChangesRequest) (*datastore.FetchRegistrationEntryChangesResponse, error) {
	if req == nil {
		return nil, errors.New("fetch registration entry changes request is required")
	}

	events, pending, err := ds.fetchChanges(ctx, &ds.registrationEntryChanges, req.EventTimeout, req.DataConsistency, RegisteredEntryEvent{}.TableName(), "entry_id")
	if err != nil {
		return nil, err
	}

	return &datastore.FetchRegistrationEntryChangesResponse{
		EntryIDs:      eventKeys(events),
		PendingEvents: pendingEventCount(pending),
	}, nil
}

func (ds *Plugin) FetchAttestedNodeChanges(ctx context.Context, req *datastore.FetchAttestedNodeChangesRequest) (*datastore.FetchAttestedNodeChangesResponse, error) {
	if req == nil {
		return nil, errors.New("fetch attested node changes request is required")
	}

	events, pending, err := ds.fetchChanges(ctx, &ds.attestedNodeChanges, req.EventTimeout, req.DataConsistency, AttestedNodeEvent{}.TableName(), "spiffe_id")
	if err != nil {
		return nil, err
	}

	return &datastore.FetchAttestedNodeChangesResponse{
		SpiffeIDs:     eventKeys(events),
		PendingEvents: pendingEventCount(pending),
	}, nil
}

// PruneEventsForTesting prunes events older than the given age.
func (ds *Plugin) PruneEventsForTesting(ctx context.Context, olderThan time.Duration) error {
	return ds.pruneEvents(ctx, olderThan)
}

func (ds *Plugin) pruneEvents(ctx context.Context, olderThan time.Duration) error {
	cutoff := ds.now().Add(-olderThan)
	return errors.Join(
		ds.withWriteTx(ctx, func(tx *gorm.DB) error {
			return pruneRegistrationEntryEvents(tx, cutoff)
		}),
		ds.withWriteTx(ctx, func(tx *gorm.DB) error {
			return pruneAttestedNodeEvents(tx, cutoff)
		}),
	)
}

func (ds *Plugin) startEventPruner() {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	if ds.pruneEventsOlderThan <= 0 || ds.stopPruner != nil {
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	ds.stopPruner = func() {
		cancel()
		<-done
	}

	go func() {
		defer close(done)
		ticker := time.NewTicker(ds.pruneEventsOlderThan / 2)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := ds.pruneEvents(ctx, ds.pruneEventsOlderThan); err != nil && ctx.Err() == nil {
					ds.log.WithError(err).Error("Failed to prune events")
				}
			}
		}
	}()
}

func (ds *Plugin) stopEventPruner() {
	ds.mu.Lock()
	stop := ds.stopPruner
	ds.stopPruner = nil
	ds.mu.Unlock()
	if stop != nil {
		stop()
	}
}

// fetchChanges serializes consumers of one event stream. All reads are made
// before the tracker is advanced so a canceled or failed call can be retried
// without losing changes.
func (ds *Plugin) fetchChanges(ctx context.Context, tracker *changeTracker, eventTimeout time.Duration, dataConsistency datastore.DataConsistency, table, keyColumn string) ([]trackedEvent, int, error) {
	tracker.mu.Lock()
	defer tracker.mu.Unlock()

	ds.mu.Lock()
	primaryDB := ds.db
	forwardDB := primaryDB
	if dataConsistency == datastore.TolerateStale && ds.roDb != nil {
		forwardDB = ds.roDb
	}
	ds.mu.Unlock()
	if primaryDB == nil {
		return nil, 0, errors.New("datastore-sql: datastore is not configured")
	}

	now := ds.now()
	firstEventID := tracker.firstEventID
	startupDeadline := tracker.startupDeadline
	startupSeen := cloneEventSet(tracker.startupSeen)
	lastEventID := tracker.lastEventID
	pending := clonePendingEvents(tracker.pending)

	for eventID, deadline := range pending {
		if !now.Before(deadline) {
			delete(pending, eventID)
		}
	}

	var startupEvents []trackedEvent
	if firstEventID != 0 && now.Before(startupDeadline) {
		var err error
		startupEvents, err = queryTrackedEvents(ctx, primaryDB, table, keyColumn, "id < ?", firstEventID)
		if err != nil {
			return nil, 0, err
		}
	} else {
		startupSeen = nil
	}

	// Failing to resolve skipped events must not block new events; the
	// skipped events stay pending and are retried on the next call.
	resolvedEvents, err := queryTrackedEventsByID(ctx, primaryDB, table, keyColumn, pending)
	if err != nil {
		if ctx.Err() != nil {
			return nil, 0, err
		}
		ds.log.WithError(err).WithField("table", table).Error("Failed to fetch skipped events")
		resolvedEvents = nil
	}

	forwardEvents, err := queryTrackedEvents(ctx, forwardDB, table, keyColumn, "id > ?", lastEventID)
	if err != nil {
		return nil, 0, err
	}

	changed := make(map[string]trackedEvent)
	for _, event := range startupEvents {
		if _, ok := startupSeen[event.id]; ok {
			continue
		}
		startupSeen[event.id] = struct{}{}
		changed[event.key] = event
	}

	for _, event := range resolvedEvents {
		if _, ok := pending[event.id]; !ok {
			continue
		}
		delete(pending, event.id)
		changed[event.key] = event
	}

	for _, event := range forwardEvents {
		if event.id <= lastEventID {
			continue
		}
		if firstEventID == 0 {
			firstEventID = event.id
			startupDeadline = now.Add(eventTimeout)
			startupSeen = make(map[uint]struct{})
		} else {
			for skipped := lastEventID + 1; skipped < event.id; skipped++ {
				pending[skipped] = now.Add(eventTimeout)
			}
		}
		lastEventID = event.id
		changed[event.key] = event
	}

	tracker.firstEventID = firstEventID
	tracker.startupDeadline = startupDeadline
	tracker.startupSeen = startupSeen
	tracker.lastEventID = lastEventID
	tracker.pending = pending

	events := make([]trackedEvent, 0, len(changed))
	for _, event := range changed {
		events = append(events, event)
	}
	return events, len(pending), nil
}

func queryTrackedEvents(ctx context.Context, db *sqlDB, table, keyColumn, predicate string, args ...any) ([]trackedEvent, error) {
	query := fmt.Sprintf("SELECT id, %s FROM %s", keyColumn, table)
	if predicate != "" {
		query += " WHERE " + predicate
	}
	query += " ORDER BY id ASC"

	rows, err := db.QueryContext(ctx, maybeRebind(db.databaseType, query), args...)
	if err != nil {
		return nil, sqlcommon.NewWrappedSQLError(err)
	}
	defer rows.Close()

	var events []trackedEvent
	for rows.Next() {
		var event trackedEvent
		if err := rows.Scan(&event.id, &event.key); err != nil {
			return nil, sqlcommon.NewWrappedSQLError(err)
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, sqlcommon.NewWrappedSQLError(err)
	}
	return events, nil
}

func queryTrackedEventsByID(ctx context.Context, db *sqlDB, table, keyColumn string, pending map[uint]time.Time) ([]trackedEvent, error) {
	ids := make([]uint, 0, len(pending))
	for id := range pending {
		ids = append(ids, id)
	}
	slices.Sort(ids)

	var events []trackedEvent
	for start := 0; start < len(ids); start += maxEventIDQuerySize {
		end := min(start+maxEventIDQuerySize, len(ids))
		args := make([]any, end-start)
		placeholders := make([]string, end-start)
		for i, id := range ids[start:end] {
			args[i] = id
			placeholders[i] = "?"
		}
		chunk, err := queryTrackedEvents(ctx, db, table, keyColumn, "id IN ("+strings.Join(placeholders, ",")+")", args...)
		if err != nil {
			return nil, err
		}
		events = append(events, chunk...)
	}
	return events, nil
}

func eventKeys(events []trackedEvent) []string {
	keys := make([]string, len(events))
	for i, event := range events {
		keys[i] = event.key
	}
	return keys
}

func cloneEventSet(in map[uint]struct{}) map[uint]struct{} {
	if in == nil {
		return nil
	}
	out := make(map[uint]struct{}, len(in))
	maps.Copy(out, in)
	return out
}

func clonePendingEvents(in map[uint]time.Time) map[uint]time.Time {
	out := make(map[uint]time.Time, len(in))
	maps.Copy(out, in)
	return out
}

func pendingEventCount(count int) int32 {
	if count > math.MaxInt32 {
		return math.MaxInt32
	}
	return int32(count) //nolint:gosec // Count is non-negative and bounded above.
}
