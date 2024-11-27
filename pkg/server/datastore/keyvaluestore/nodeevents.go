package keyvaluestore

import (
	"context"
	"errors"
	"time"

	"encoding/json"
	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/pkg/server/datastore/keyvaluestore/internal/keyvalue"
	"github.com/spiffe/spire/pkg/server/datastore/keyvaluestore/internal/record"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"strconv"
)

// ListAttestedNodeEvents lists all attested node events
func (ds *DataStore) ListAttestedNodeEvents(ctx context.Context, req *datastore.ListAttestedNodeEventsRequest) (*datastore.ListAttestedNodeEventsResponse, error) {
	records, _, err := ds.nodeEvents.List(ctx, &listAttestedNodeEventsRequest{
		ListAttestedNodeEventsRequest: *req,
	})

	if err != nil {
		return nil, err
	}

	resp := &datastore.ListAttestedNodeEventsResponse{}

	resp.Events = make([]datastore.AttestedNodeEvent, 0, len(records))
	for _, record := range records {
		resp.Events = append(resp.Events, *record.Object.NodeEvent)
	}
	return resp, nil
}

// PruneAttestedNodeEvents deletes all attested node events older than a specified duration (i.e. more than 24 hours old)
func (ds *DataStore) PruneAttestedNodeEvents(ctx context.Context, olderThan time.Duration) error {
	records, _, err := ds.nodeEvents.List(ctx, &listAttestedNodeEventsRequest{
		ByCreatedBefore: time.Now().Add(-olderThan),
	})
	if err != nil {
		return err
	}

	var errCount int
	var firstErr error
	for _, record := range records {
		if err := ds.nodeEvents.Delete(ctx, record.Object.ContentKey); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			errCount++
		}
	}

	if firstErr != nil {
		return dsErr(firstErr, "failed pruning %d of %d attested node events: first error:", errCount, len(records))
	}
	return nil
}

// FetchAttestedNodeEvent fetches an existing attested node event by event ID
func (ds *DataStore) FetchAttestedNodeEvent(ctx context.Context, eventID uint) (*datastore.AttestedNodeEvent, error) {
	r, err := ds.nodeEvents.Get(ctx, eventIDtoKey(eventID))
	switch {
	case err == nil:
		return r.Object.NodeEvent, nil
	case errors.Is(err, record.ErrNotFound):
		return nil, nil
	default:
		return nil, dsErr(err, "failed to fetch attested node event")
	}
}

// CreateAttestedNodeEventForTesting creates an attested node event. Used for unit testing.
func (ds *DataStore) CreateAttestedNodeEventForTesting(ctx context.Context, event *datastore.AttestedNodeEvent) error {
	return ds.createAttestedNodeEvent(ctx, event)
}

func (ds *DataStore) createAttestedNodeEvent(ctx context.Context, event *datastore.AttestedNodeEvent) error {
	id, err := ds.store.AtomicCounter(ctx, ds.nodeEvents.Kind())
	if err != nil {
		return dsErr(err, "failed to create attested node event")
	}
	event.EventID = id

	if err := ds.nodeEvents.Create(ctx, makeNodeEventObject(event)); err != nil {
		return dsErr(err, "failed to create attested node event")
	}

	return nil
}

func (ds *DataStore) DeleteAttestedNodeEventForTesting(ctx context.Context, eventID uint) error {
	return ds.deleteAttestedNodeEventForTesting(ctx, eventID)
}

func (ds *DataStore) deleteAttestedNodeEventForTesting(ctx context.Context, eventID uint) error {
	if err := ds.nodeEvents.Delete(ctx, eventIDtoKey(eventID)); err != nil {
		return dsErr(err, "failed to delete attested node event")
	}

	return nil
}

type attestedNodeEventWrapper struct {
	EventID  uint   `json:"eventID"`
	SpiffeID string `json:"spiffeID"`
}

type nodeEventCodec struct{}

func (nodeEventCodec) Marshal(in *nodeEventObject) (string, []byte, error) {
	wrappedEvent := &attestedNodeEventWrapper{
		EventID:  in.NodeEvent.EventID,
		SpiffeID: in.NodeEvent.SpiffeID,
	}

	out, err := json.Marshal(wrappedEvent)
	if err != nil {
		return "", nil, err
	}
	return in.ContentKey, out, nil
}

func (nodeEventCodec) Unmarshal(in []byte, out *nodeEventObject) error {
	wrappedNode := new(attestedNodeEventWrapper)

	if err := json.Unmarshal(in, wrappedNode); err != nil {
		return err
	}

	out.NodeEvent = &datastore.AttestedNodeEvent{
		EventID:  wrappedNode.EventID,
		SpiffeID: wrappedNode.SpiffeID,
	}

	out.ContentKey = eventIDtoKey(out.NodeEvent.EventID)
	return nil
}

type nodeEventObject struct {
	ContentKey string
	NodeEvent  *datastore.AttestedNodeEvent
}

func makeNodeEventObject(event *datastore.AttestedNodeEvent) nodeEventObject {
	return nodeEventObject{
		ContentKey: eventIDtoKey(event.EventID),
		NodeEvent:  event,
	}
}

func (r nodeEventObject) Key() string { return r.ContentKey }

func eventIDtoKey(eventID uint) string {
	return strconv.FormatUint(uint64(eventID), 10)
}

type listAttestedNodeEventsRequest struct {
	datastore.ListAttestedNodeEventsRequest
	ByCreatedBefore time.Time
}

type nodeEventIndex struct {
	eventID   record.UnaryIndex[uint]
	createdAt record.UnaryIndex[time.Time]
}

func (idx *nodeEventIndex) SetUp() {
	idx.eventID.SetQuery("Object.NodeEvent.EventID")
	idx.createdAt.SetQuery("CreatedAt")
}

func (c *nodeEventIndex) Get(obj *record.Record[nodeEventObject]) {

}

func (idx *nodeEventIndex) List(req *listAttestedNodeEventsRequest) (*keyvalue.ListObject, error) {
	if req.GreaterThanEventID != 0 && req.LessThanEventID != 0 {
		return nil, status.Errorf(codes.Unknown, "datastore-keyvalue: can't set both greater and less than event id")
	}

	list := new(keyvalue.ListObject)

	if req.LessThanEventID != 0 {
		list.Filters = append(list.Filters, idx.eventID.LessThan(req.LessThanEventID))
	}

	if req.GreaterThanEventID != 0 {
		list.Filters = append(list.Filters, idx.eventID.GreaterThan(req.GreaterThanEventID))
	}

	if !req.ByCreatedBefore.IsZero() {
		list.Filters = append(list.Filters, idx.createdAt.LessThan(req.ByCreatedBefore.UTC()))
	}

	return list, nil
}
