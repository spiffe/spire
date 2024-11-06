package keyvaluestore

import (
	"context"
	"errors"
	"time"
	"unicode"

	"github.com/gofrs/uuid/v5"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/pkg/server/datastore/keyvaluestore/internal/keyvalue"
	"github.com/spiffe/spire/pkg/server/datastore/keyvaluestore/internal/record"
	"github.com/spiffe/spire/proto/spire/common"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

func (ds *DataStore) CountRegistrationEntries(ctx context.Context, req *datastore.CountRegistrationEntriesRequest) (int32, error) {
	if req.BySelectors != nil && len(req.BySelectors.Selectors) == 0 {
		return 0, status.Error(codes.InvalidArgument, "cannot list by empty selector set")
	}

	listReq := &listRegistrationEntries{
		ListRegistrationEntriesRequest: datastore.ListRegistrationEntriesRequest{
			DataConsistency: req.DataConsistency,
			ByParentID:      req.ByParentID,
			BySelectors:     req.BySelectors,
			BySpiffeID:      req.BySpiffeID,
			ByFederatesWith: req.ByFederatesWith,
			ByHint:          req.ByHint,
			ByDownstream:    req.ByDownstream,
		},
	}

	records, _, err := ds.entries.List(ctx, listReq)
	return int32(len(records)), err
}

func (ds *DataStore) CreateRegistrationEntry(ctx context.Context, entry *common.RegistrationEntry) (*common.RegistrationEntry, error) {
	if err := validateRegistrationEntry(entry); err != nil {
		return nil, err
	}

	return ds.createRegistrationEntry(ctx, entry)
}

func (ds *DataStore) createRegistrationEntry(ctx context.Context, entry *common.RegistrationEntry) (*common.RegistrationEntry, error) {
	entryID, err := createOrReturnEntryID(entry)
	if err != nil {
		return nil, err
	}

	entry.EntryId = entryID

	if err := ds.entries.Create(ctx, entryObject{Entry: entry}); err != nil {
		return nil, dsErr(err, "failed to create entry")
	}

	if err = ds.createRegistrationEntryEvent(ctx, &datastore.RegistrationEntryEvent{
		EntryID: entry.EntryId,
	}); err != nil {
		return nil, err
	}

	return entry, nil
}

func (ds *DataStore) CreateOrReturnRegistrationEntry(ctx context.Context, entry *common.RegistrationEntry) (*common.RegistrationEntry, bool, error) {
	if err := validateRegistrationEntry(entry); err != nil {
		return nil, false, err
	}

	records, _, err := ds.entries.List(ctx, &listRegistrationEntries{
		ListRegistrationEntriesRequest: datastore.ListRegistrationEntriesRequest{
			BySpiffeID: entry.SpiffeId,
			ByParentID: entry.ParentId,
			BySelectors: &datastore.BySelectors{
				Match:     datastore.Exact,
				Selectors: entry.Selectors,
			},
		},
	})

	if err != nil && len(records) > 0 {
		return records[0].Object.Entry, true, nil
	}

	newEntry, err := ds.createRegistrationEntry(ctx, entry)
	if err != nil {
		return nil, false, err
	}
	return newEntry, false, err
}

func (ds *DataStore) DeleteRegistrationEntry(ctx context.Context, entryID string) (*common.RegistrationEntry, error) {
	r, err := ds.entries.Get(ctx, entryID)

	if err != nil {
		return nil, dsErr(err, "failed to delete entry")
	}

	if err := ds.entries.Delete(ctx, entryID); err != nil {
		return nil, dsErr(err, "failed to delete entry")
	}

	if ds.createRegistrationEntryEvent(ctx, &datastore.RegistrationEntryEvent{
		EntryID: entryID,
	}); err != nil {
		return nil, err
	}

	return r.Object.Entry, nil
}

func (ds *DataStore) FetchRegistrationEntry(ctx context.Context, entryID string) (*common.RegistrationEntry, error) {
	r, err := ds.entries.Get(ctx, entryID)
	switch {
	case err == nil:
		return r.Object.Entry, nil
	case errors.Is(err, record.ErrNotFound):
		return nil, nil
	default:
		return nil, dsErr(err, "failed to fetch entry")
	}
}

func (ds *DataStore) ListRegistrationEntries(ctx context.Context, req *datastore.ListRegistrationEntriesRequest) (*datastore.ListRegistrationEntriesResponse, error) {
	records, cursor, err := ds.entries.List(ctx, &listRegistrationEntries{
		ListRegistrationEntriesRequest: *req,
	})
	if err != nil {
		return nil, err
	}
	resp := &datastore.ListRegistrationEntriesResponse{
		Pagination: newPagination(req.Pagination, cursor),
	}
	resp.Entries = make([]*common.RegistrationEntry, 0, len(records))
	for _, record := range records {
		resp.Entries = append(resp.Entries, record.Object.Entry)
	}
	return resp, nil
}

func (ds *DataStore) PruneRegistrationEntries(ctx context.Context, expiresBefore time.Time) error {
	records, _, err := ds.entries.List(ctx, &listRegistrationEntries{
		ByExpiresBefore: expiresBefore,
	})
	if err != nil {
		return err
	}

	var errCount int
	var firstErr error
	for _, record := range records {
		entry := record.Object.Entry
		if err := ds.entries.Delete(ctx, entry.EntryId); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			errCount++
		}

		if err := ds.createRegistrationEntryEvent(ctx, &datastore.RegistrationEntryEvent{
			EntryID: entry.EntryId,
		}); err != nil {
			return err
		}
		ds.log.WithFields(logrus.Fields{
			telemetry.SPIFFEID:       entry.SpiffeId,
			telemetry.ParentID:       entry.ParentId,
			telemetry.RegistrationID: entry.EntryId,
		}).Info("Pruned an expired registration")
	}

	if firstErr != nil {
		return dsErr(firstErr, "failed pruning %d of %d entries: first error:", errCount, len(records))
	}
	return nil
}

func createOrReturnEntryID(entry *common.RegistrationEntry) (string, error) {
	if entry.EntryId != "" {
		return entry.EntryId, nil
	}

	return newRegistrationEntryID()
}

func newRegistrationEntryID() (string, error) {
	u, err := uuid.NewV4()
	if err != nil {
		return "", err
	}
	return u.String(), nil
}

func (ds *DataStore) UpdateRegistrationEntry(ctx context.Context, newEntry *common.RegistrationEntry, mask *common.RegistrationEntryMask) (*common.RegistrationEntry, error) {
	if err := validateRegistrationEntryForUpdate(newEntry, mask); err != nil {
		return nil, dsErr(err, "failed to update entry")
	}

	existing, err := ds.entries.Get(ctx, newEntry.EntryId)
	if err != nil {
		return nil, dsErr(err, "failed to update entry")
	}

	updated := existing.Object

	if mask == nil || mask.StoreSvid {
		updated.Entry.StoreSvid = newEntry.StoreSvid
	}

	if mask == nil || mask.Selectors {
		updated.Entry.Selectors = newEntry.Selectors
	}

	if mask == nil || mask.DnsNames {
		updated.Entry.DnsNames = newEntry.DnsNames
	}

	if mask == nil || mask.SpiffeId {
		updated.Entry.SpiffeId = newEntry.SpiffeId
	}

	if mask == nil || mask.ParentId {
		updated.Entry.ParentId = newEntry.ParentId
	}

	if mask == nil || mask.X509SvidTtl {
		updated.Entry.X509SvidTtl = newEntry.X509SvidTtl
	}

	if mask == nil || mask.Admin {
		updated.Entry.Admin = newEntry.Admin
	}

	if mask == nil || mask.Downstream {
		updated.Entry.Downstream = newEntry.Downstream
	}

	if mask == nil || mask.EntryExpiry {
		updated.Entry.EntryExpiry = newEntry.EntryExpiry
	}

	if mask == nil || mask.JwtSvidTtl {
		updated.Entry.JwtSvidTtl = newEntry.JwtSvidTtl
	}

	if mask == nil || mask.Hint {
		updated.Entry.Hint = newEntry.Hint
	}

	if mask == nil || mask.FederatesWith {
		updated.Entry.FederatesWith = newEntry.FederatesWith
	}

	if err := ds.entries.Update(ctx, updated, existing.Metadata.Revision); err != nil {
		return nil, dsErr(err, "failed to update entry")
	}

	if err = ds.createRegistrationEntryEvent(ctx, &datastore.RegistrationEntryEvent{
		EntryID: newEntry.EntryId,
	}); err != nil {
		return nil, err
	}

	return updated.Entry, nil
}

func validateRegistrationEntry(entry *common.RegistrationEntry) error {
	if entry == nil {
		return kvError.New("invalid request: missing registered entry")
	}

	if len(entry.Selectors) == 0 {
		return kvError.New("invalid registration entry: missing selector list")
	}

	// In case of StoreSvid is set, all entries 'must' be the same type,
	// it is done to avoid users to mix selectors from different platforms in
	// entries with storable SVIDs
	if entry.StoreSvid {
		// Selectors must never be empty
		tpe := entry.Selectors[0].Type
		for _, t := range entry.Selectors {
			if tpe != t.Type {
				return kvError.New("invalid registration entry: selector types must be the same when store SVID is enabled")
			}
		}
	}

	if len(entry.EntryId) > 255 {
		return kvError.New("invalid registration entry: entry ID too long")
	}

	for _, e := range entry.EntryId {
		if !unicode.In(e, validEntryIDChars) {
			return kvError.New("invalid registration entry: entry ID contains invalid characters")
		}
	}

	if len(entry.SpiffeId) == 0 {
		return kvError.New("invalid registration entry: missing SPIFFE ID")
	}

	if entry.X509SvidTtl < 0 {
		return kvError.New("invalid registration entry: X509SvidTtl is not set")
	}

	if entry.JwtSvidTtl < 0 {
		return kvError.New("invalid registration entry: JwtSvidTtl is not set")
	}

	return nil
}

func validateRegistrationEntryForUpdate(entry *common.RegistrationEntry, mask *common.RegistrationEntryMask) error {
	if entry == nil {
		return kvError.New("invalid request: missing registered entry")
	}

	if (mask == nil || mask.Selectors) && len(entry.Selectors) == 0 {
		return kvError.New("invalid registration entry: missing selector list")
	}

	if (mask == nil || mask.SpiffeId) &&
		entry.SpiffeId == "" {
		return kvError.New("invalid registration entry: missing SPIFFE ID")
	}

	if (mask == nil || mask.X509SvidTtl) &&
		(entry.X509SvidTtl < 0) {
		return kvError.New("invalid registration entry: X509SvidTtl is not set")
	}

	if (mask == nil || mask.JwtSvidTtl) &&
		(entry.JwtSvidTtl < 0) {
		return kvError.New("invalid registration entry: JwtSvidTtl is not set")
	}

	return nil
}

type entryObject struct {
	Entry *common.RegistrationEntry
}

func (o entryObject) Key() string {
	return o.Entry.EntryId
}

type entryCodec struct{}

func (entryCodec) Marshal(in *entryObject) (string, []byte, error) {
	out, err := proto.Marshal(in.Entry)
	if err != nil {
		return "", nil, err
	}
	return in.Entry.EntryId, out, nil
}

func (entryCodec) Unmarshal(in []byte, out *entryObject) error {
	entry := new(common.RegistrationEntry)
	if err := proto.Unmarshal(in, entry); err != nil {
		return err
	}
	out.Entry = entry
	return nil
}

type listRegistrationEntries struct {
	datastore.ListRegistrationEntriesRequest
	ByExpiresBefore time.Time
}

type entryIndex struct {
	parentID      record.UnaryIndex[string]
	spiffeID      record.UnaryIndex[string]
	selectors     record.MultiIndex[*common.Selector]
	federatesWith record.MultiIndex[string]
	expiresAt     record.UnaryIndex[int64]
	hint          record.UnaryIndex[string]
	downstream    record.UnaryIndex[bool]
}

func (c *entryIndex) SetUp() {
	/*r.Object.Entry.RevisionNumber = r.Metadata.Revision*/

	c.parentID.SetQuerry("Object.Entry.ParentId")
	c.spiffeID.SetQuerry("Object.Entry.SpiffeId")
	c.selectors.SetQuerry("Object.Entry.Selectors")
	c.federatesWith.SetQuerry("Object.Entry.FederatesWith")
	c.expiresAt.SetQuerry("Object.Entry.EntryExpiry")
	c.hint.SetQuerry("Object.Entry.Hint")
	c.downstream.SetQuerry("Object.Entry.Downstream")
}

func (c *entryIndex) List(req *listRegistrationEntries) (*keyvalue.ListObject, error) {
	cursor, limit, err := getPaginationParams(req.Pagination)
	if err != nil {
		return nil, err
	}

	list := new(keyvalue.ListObject)

	list.Cursor = cursor
	list.Limit = limit

	if req.ByParentID != "" {
		list.Filters = append(list.Filters, c.parentID.EqualTo(req.ByParentID))
	}
	if req.BySelectors != nil {
		list.Filters = append(list.Filters, c.selectors.Matching(req.BySelectors.Selectors, matchBehavior(req.BySelectors.Match)))
	}
	if req.BySpiffeID != "" {
		list.Filters = append(list.Filters, c.spiffeID.EqualTo(req.BySpiffeID))
	}
	if req.ByFederatesWith != nil {
		list.Filters = append(list.Filters, c.federatesWith.Matching(req.ByFederatesWith.TrustDomains, matchBehavior(req.ByFederatesWith.Match)))
	}
	if req.ByHint != "" {
		list.Filters = append(list.Filters, c.hint.EqualTo(req.ByHint))
	}
	if req.ByDownstream != nil {
		list.Filters = append(list.Filters, c.downstream.EqualTo(*req.ByDownstream))
	}

	if !req.ByExpiresBefore.IsZero() {
		list.Filters = append(list.Filters, c.expiresAt.LessThan(req.ByExpiresBefore.Unix()))
	}

	return list, nil
}
