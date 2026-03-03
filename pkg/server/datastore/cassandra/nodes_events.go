package cassandra

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	gocql "github.com/apache/cassandra-gocql-driver/v2"
	datastorev1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/datastore/v1alpha1"
)

func (p *Plugin) ListAttestedNodeEvents(
	ctx context.Context,
	req *datastorev1.ListAttestedNodeEventsRequest,
) (*datastorev1.ListAttestedNodeEventsResponse, error) {
	if req == nil {
		return nil, errors.New("request is required")
	}

	b := strings.Builder{}
	b.WriteString("SELECT event_id, spiffe_id, created_at FROM attested_node_entries_events ")
	var args []any

	switch {
	case req.GetGreaterThanEventId() > 0 && req.GetLessThanEventId() > 0:
		return nil, errors.New("can't set both greater and less than event id")
	case req.GetLessThanEventId() > 0:
		b.WriteString("WHERE event_id < ? ")
		args = append(args, req.GetLessThanEventId())
	case req.GetGreaterThanEventId() > 0:
		b.WriteString("WHERE event_id > ? ")
		args = append(args, req.GetGreaterThanEventId())
	}
	b.WriteString(" ALLOW FILTERING")

	iter := p.db.session.Query(b.String(), args...).Consistency(p.db.cfg.ReadConsistency).IterContext(ctx)
	scanner := iter.Scanner()
	events := make([]*datastorev1.AttestedNodeEvent, 0)

	for scanner.Next() {
		var (
			eventID   uint
			spiffeID  string
			createdAt time.Time
		)

		if err := scanner.Scan(
			&eventID,
			&spiffeID,
			&createdAt,
		); err != nil {
			return nil, err
		}

		events = append(events, &datastorev1.AttestedNodeEvent{
			EventId:   uint64(eventID),
			SpiffeId:  spiffeID,
			CreatedAt: createdAt.Unix(),
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	slices.SortStableFunc(events, func(a, b *datastorev1.AttestedNodeEvent) int {
		if a.EventId < b.EventId {
			return -1
		}
		if a.EventId > b.EventId {
			return 1
		}
		return 0
	})

	dsEvents := make([]*datastorev1.AttestedNodeEvent, len(events))
	for i := range events {
		dsEvents[i] = &datastorev1.AttestedNodeEvent{
			EventId:  uint64(events[i].EventId),
			SpiffeId: events[i].SpiffeId,
		}
	}

	return &datastorev1.ListAttestedNodeEventsResponse{
		Events: dsEvents,
	}, nil
}

func (p *Plugin) createAttestedNodeEvent(ctx context.Context, event *datastorev1.AttestedNodeEvent) error {
	if event.EventId == 0 {
		nextID, err := p.getNextAttestedNodeEventID(ctx)
		if err != nil {
			return err
		}
		event.EventId = nextID
	}

	query := `INSERT INTO attested_node_entries_events (event_id, created_at, updated_at, spiffe_id) VALUES (?, ?, ?, ?)`
	if err := p.db.session.Query(query,
		event.EventId,
		time.Now().UTC(),
		time.Now().UTC(),
		event.SpiffeId,
	).Consistency(p.db.cfg.WriteConsistency).ExecContext(ctx); err != nil {
		return newCassandraError("failed to create attested node event: %s", err.Error())
	}

	return nil
}

func (p *Plugin) getNextAttestedNodeEventID(ctx context.Context) (uint64, error) {
	q := `SELECT max(event_id) FROM attested_node_entries_events ALLOW FILTERING`

	var maxID *uint64
	if err := p.db.session.Query(q).Consistency(p.db.cfg.ReadConsistency).ScanContext(ctx, &maxID); err != nil && err != gocql.ErrNotFound {
		return 0, newCassandraError("failed to get max attested node event ID: %s", err.Error())
	}
	if maxID == nil {
		return 1, nil
	}

	return uint64(*maxID) + 1, nil
}

func (p *Plugin) PruneAttestedNodeEvents(ctx context.Context, req *datastorev1.PruneAttestedNodeEventsRequest) (*datastorev1.PruneAttestedNodeEventsResponse, error) {
	cutoff := time.Now().UTC().Add(-time.Duration(req.OlderThan * int64(time.Second)))

	idsQ := `SELECT event_id, spiffe_id FROM attested_node_entries_events WHERE created_at < ? ALLOW FILTERING`
	scanner := p.db.session.Query(idsQ, cutoff).Consistency(p.db.cfg.ReadConsistency).IterContext(ctx).Scanner()

	var events []*datastorev1.AttestedNodeEvent
	for scanner.Next() {
		event := new(datastorev1.AttestedNodeEvent)
		if err := scanner.Scan(&event.EventId, &event.SpiffeId); err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	b := p.db.session.Batch(gocql.LoggedBatch).Consistency(p.db.cfg.WriteConsistency)
	deleteQ := `DELETE FROM attested_node_entries_events WHERE spiffe_id = ? AND event_id = ?`
	for _, event := range events {
		b.Entries = append(b.Entries, gocql.BatchEntry{
			Stmt:       deleteQ,
			Args:       []any{event.SpiffeId, event.EventId},
			Idempotent: true,
		})
	}
	if err := b.ExecContext(ctx); err != nil {
		return nil, err
	}

	return &datastorev1.PruneAttestedNodeEventsResponse{}, nil
}

func (p *Plugin) FetchAttestedNodeEvent(ctx context.Context, req *datastorev1.FetchAttestedNodeEventRequest) (*datastorev1.FetchAttestedNodeEventResponse, error) {
	q := `SELECT event_id, spiffe_id FROM attested_node_entries_events WHERE event_id = ?`

	var event datastorev1.AttestedNodeEvent
	if err := p.db.session.Query(q, req.EventId).Consistency(p.db.cfg.ReadConsistency).ScanContext(ctx,
		&event.EventId,
		&event.SpiffeId,
	); err != nil {
		if err == gocql.ErrNotFound {
			return nil, NotFoundErr
		}
		return nil, newCassandraError("failed to fetch attested node event: %s", err.Error())
	}

	return &datastorev1.FetchAttestedNodeEventResponse{
		Event: &event,
	}, nil
}

func (p *Plugin) CreateAttestedNodeEvent(ctx context.Context, req *datastorev1.CreateAttestedNodeEventRequest) (*datastorev1.CreateAttestedNodeEventResponse, error) {
	err := p.createAttestedNodeEvent(ctx, &datastorev1.AttestedNodeEvent{
		EventId:  req.Event.EventId,
		SpiffeId: req.Event.SpiffeId,
	})
	if err != nil {
		return nil, err
	}

	return &datastorev1.CreateAttestedNodeEventResponse{}, nil
}

func (p *Plugin) DeleteAttestedNodeEvent(ctx context.Context, req *datastorev1.DeleteAttestedNodeEventRequest) (*datastorev1.DeleteAttestedNodeEventResponse, error) {
	findEventQ := `SELECT spiffe_id FROM attested_node_entries_events WHERE event_id = ?`

	var spiffeID string
	if err := p.db.session.Query(findEventQ, req.EventId).
		Consistency(p.db.cfg.ReadConsistency).
		ScanContext(ctx, &spiffeID); err != nil {
		if err == gocql.ErrNotFound {
			return nil, NotFoundErr
		}
		return nil, newCassandraError("failed to find attested node event for deletion: %s", err.Error())
	}

	deleteQ := `DELETE FROM attested_node_entries_events WHERE spiffe_id = ? AND event_id = ?`
	if err := p.db.session.Query(
		deleteQ,
		spiffeID,
		req.EventId,
	).Consistency(p.db.cfg.WriteConsistency).ExecContext(ctx); err != nil {
		return nil, newCassandraError("failed to delete attested node event: %s", err.Error())
	}

	return &datastorev1.DeleteAttestedNodeEventResponse{}, nil
}
