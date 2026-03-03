package cassandra

import (
	"context"
	"slices"
	"strings"
	"time"

	gocql "github.com/apache/cassandra-gocql-driver/v2"
	datastorev1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/datastore/v1alpha1"
)

func (p *Plugin) ListRegistrationEntryEvents(ctx context.Context, req *datastorev1.ListRegistrationEntryEventsRequest) (*datastorev1.ListRegistrationEntryEventsResponse, error) {
	b := strings.Builder{}
	b.WriteString("SELECT id, entry_id FROM registration_entry_events ")
	var args []any

	switch {
	case req.GetLessThanEventId() > 0 && req.GetGreaterThanEventId() > 0:
		return nil, newCassandraError("can't set both greater and less than event id")
	case req.GetLessThanEventId() > 0:
		b.WriteString("WHERE id < ? ")
		args = append(args, req.GetLessThanEventId())
	case req.GetGreaterThanEventId() > 0:
		b.WriteString("WHERE id > ? ")
		args = append(args, req.GetGreaterThanEventId())
	}
	b.WriteString(" ALLOW FILTERING")

	iter := p.db.session.Query(b.String(), args...).Consistency(p.db.cfg.ReadConsistency).IterContext(ctx)
	scanner := iter.Scanner()
	events := make([]*datastorev1.RegistrationEntryEvent, 0)

	for scanner.Next() {
		event := new(datastorev1.RegistrationEntryEvent)
		if err := scanner.Scan(
			&event.EventId,
			&event.EntryId,
		); err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	slices.SortStableFunc(events, func(a, b *datastorev1.RegistrationEntryEvent) int {
		if a.EventId < b.EventId {
			return -1
		} else if a.EventId > b.EventId {
			return 1
		}
		return 0
	})

	resp := &datastorev1.ListRegistrationEntryEventsResponse{
		Events: events,
	}

	return resp, nil

}

func (p *Plugin) createRegistrationEntryEvent(ctx context.Context, event *datastorev1.RegistrationEntryEvent) error {
	if event.EventId == 0 {
		nextID, err := p.getNextRegistrationEntryEventID(ctx)
		if err != nil {
			return err
		}
		event.EventId = nextID
	}

	q := `INSERT INTO registration_entry_events (id, entry_id, created_at, updated_at) VALUES (?, ?, ?, ?)`
	if err := p.db.session.Query(q,
		event.EventId,
		event.EntryId,
		time.Now().UTC(),
		time.Now().UTC(),
	).Consistency(p.db.cfg.WriteConsistency).ExecContext(ctx); err != nil {
		return err
	}

	return nil
}

func (p *Plugin) getNextRegistrationEntryEventID(ctx context.Context) (uint64, error) {
	q := `SELECT max(id) FROM registration_entry_events ALLOW FILTERING`

	var maxID *uint
	if err := p.db.session.Query(q).Consistency(p.db.cfg.ReadConsistency).ScanContext(ctx, &maxID); err != nil {
		return 0, err
	}
	if maxID == nil {
		return 1, nil
	}
	return uint64(*maxID) + 1, nil
}

func (p *Plugin) PruneRegistrationEntryEvents(ctx context.Context, req *datastorev1.PruneRegistrationEntryEventsRequest) (*datastorev1.PruneRegistrationEntryEventsResponse, error) {
	cutoff := time.Now().UTC().Add(-time.Duration(req.ExpiresBefore * int64(time.Second)))

	idsQ := `SELECT id, entry_id FROM registration_entry_events WHERE created_at < ? ALLOW FILTERING`
	scanner := p.db.session.Query(idsQ, cutoff).Consistency(p.db.cfg.ReadConsistency).IterContext(ctx).Scanner()

	var events []datastorev1.RegistrationEntryEvent
	for scanner.Next() {
		var event datastorev1.RegistrationEntryEvent
		if err := scanner.Scan(&event.EventId, &event.EntryId); err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	b := p.db.session.Batch(gocql.LoggedBatch).Consistency(p.db.cfg.WriteConsistency)
	deleteQ := `DELETE FROM registration_entry_events WHERE entry_id = ? AND id = ?`
	for _, event := range events {
		b.Entries = append(b.Entries, gocql.BatchEntry{
			Stmt:       deleteQ,
			Args:       []any{event.EntryId, event.EventId},
			Idempotent: true,
		})
	}
	if err := b.ExecContext(ctx); err != nil {
		return nil, err
	}

	return &datastorev1.PruneRegistrationEntryEventsResponse{}, nil
}

func (p *Plugin) FetchRegistrationEntryEvent(ctx context.Context, req *datastorev1.FetchRegistrationEntryEventRequest) (*datastorev1.FetchRegistrationEntryEventResponse, error) {
	q := `SELECT id, entry_id FROM registration_entry_events WHERE id = ?`

	var event datastorev1.RegistrationEntryEvent
	if err := p.db.session.Query(q, req.EventId).Consistency(p.db.cfg.ReadConsistency).ScanContext(ctx,
		&event.EventId,
		&event.EntryId,
	); err != nil {
		if err == gocql.ErrNotFound {
			return nil, NotFoundErr
		}
		return nil, err
	}

	return &datastorev1.FetchRegistrationEntryEventResponse{
		Event: &event,
	}, nil

}
func (p *Plugin) CreateRegistrationEntryEvent(ctx context.Context, req *datastorev1.CreateRegistrationEntryEventRequest) (*datastorev1.CreateRegistrationEntryEventResponse, error) {
	return nil, p.createRegistrationEntryEvent(ctx, req.Event)
}

func (p *Plugin) DeleteRegistrationEntryEvent(ctx context.Context, req *datastorev1.DeleteRegistrationEntryEventRequest) (*datastorev1.DeleteRegistrationEntryEventResponse, error) {
	q := `DELETE FROM registration_entry_events WHERE id = ?`
	if err := p.db.session.Query(q, req.EventId).Consistency(p.db.cfg.WriteConsistency).ExecContext(ctx); err != nil {
		return nil, err
	}
	return &datastorev1.DeleteRegistrationEntryEventResponse{}, nil
}
