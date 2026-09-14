package cassandra

import (
	"context"
	"slices"
	"time"

	gocql "github.com/apache/cassandra-gocql-driver/v2"
	datastorev1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/datastore/v1alpha1"
	"github.com/tjons/cassandra-toolbox/qb"
)

func (p *Plugin) ListRegistrationEntryEvents(
	ctx context.Context,
	req *datastorev1.ListRegistrationEntryEventsRequest,
) (*datastorev1.ListRegistrationEntryEventsResponse, error) {
	listQuery := qb.NewSelect().
		From("registration_entry_events").
		Columns([]string{"id", "entry_id"}).
		AllowFiltering()

	switch {
	case req.GetLessThanEventId() > 0 && req.GetGreaterThanEventId() > 0:
		return nil, newCassandraError("can't set both greater and less than event id")
	case req.GetLessThanEventId() > 0:
		listQuery.Where("id", qb.LessThan(req.GetLessThanEventId()))
	case req.GetGreaterThanEventId() > 0:
		listQuery.Where("id", qb.GreaterThan(req.GetGreaterThanEventId()))
	}

	iter := p.db.ReadQuery(listQuery).IterContext(ctx)
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

	insertQuery := qb.NewInsert().
		Into("registration_entry_events").
		SetColumn("id", event.EventId).
		SetColumn("entry_id", event.EntryId).
		SetColumn("created_at", qb.CqlFunction("toTimestamp(now())")).
		SetColumn("updated_at", qb.CqlFunction("toTimestamp(now())"))

	if err := p.db.WriteQuery(insertQuery).ExecContext(ctx); err != nil {
		return err
	}

	return nil
}

func (p *Plugin) getNextRegistrationEntryEventID(ctx context.Context) (uint64, error) {
	idQuery := qb.NewSelect().
		Column("max(id)").
		From("registration_entry_events").
		AllowFiltering()

	var maxID *uint
	if err := p.db.ReadQuery(idQuery).ScanContext(ctx, &maxID); err != nil {
		return 0, err
	}
	if maxID == nil {
		return 1, nil
	}
	return uint64(*maxID) + 1, nil
}

func (p *Plugin) PruneRegistrationEntryEvents(ctx context.Context, req *datastorev1.PruneRegistrationEntryEventsRequest) (*datastorev1.PruneRegistrationEntryEventsResponse, error) {
	cutoff := time.Now().UTC().Add(-time.Duration(req.ExpiresBefore * int64(time.Second)))

	idsQuery := qb.NewSelect().
		From("registration_entry_events").
		Columns([]string{"id", "entry_id"}).
		Where("created_at", qb.LessThan(cutoff)).
		AllowFiltering()
	scanner := p.db.ReadQuery(idsQuery).IterContext(ctx).Scanner()

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
	for _, event := range events {
		deleteQuery := qb.NewDelete().
			From("registration_entry_events").
			Where("entry_id", qb.Equals(event.EntryId)).
			Where("id", qb.Equals(event.EventId))

		b.Entries = append(b.Entries, gocql.BatchEntry{
			Stmt:       deleteQuery.ToCQL(),
			Args:       deleteQuery.QueryValues(),
			Idempotent: true,
		})
	}
	if err := b.ExecContext(ctx); err != nil {
		return nil, err
	}

	return &datastorev1.PruneRegistrationEntryEventsResponse{}, nil
}

func (p *Plugin) FetchRegistrationEntryEvent(ctx context.Context, req *datastorev1.FetchRegistrationEntryEventRequest) (*datastorev1.FetchRegistrationEntryEventResponse, error) {
	query := qb.NewSelect().
		From("registration_entry_events").
		Columns([]string{"id", "entry_id"}).
		Where("id", qb.Equals(req.GetEventId()))

	var event datastorev1.RegistrationEntryEvent
	if err := p.db.ReadQuery(query).ScanContext(ctx,
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
func (p *Plugin) CreateRegistrationEntryEvent(
	ctx context.Context,
	req *datastorev1.CreateRegistrationEntryEventRequest,
) (*datastorev1.CreateRegistrationEntryEventResponse, error) {
	return nil, p.createRegistrationEntryEvent(ctx, req.Event)
}

func (p *Plugin) DeleteRegistrationEntryEvent(
	ctx context.Context,
	req *datastorev1.DeleteRegistrationEntryEventRequest,
) (*datastorev1.DeleteRegistrationEntryEventResponse, error) {
	query := qb.NewDelete().From("registration_entry_events").Where("id", qb.Equals(req.GetEventId()))
	if err := p.db.WriteQuery(query).ExecContext(ctx); err != nil {
		return nil, err
	}
	return &datastorev1.DeleteRegistrationEntryEventResponse{}, nil
}
