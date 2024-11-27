package keyvaluestore

import (
	"context"
	"errors"
	"fmt"
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

// CountRegistrationEntries counts all registrations (pagination available)
func (ds *DataStore) CountRegistrationEntries(ctx context.Context, req *datastore.CountRegistrationEntriesRequest) (int32, error) {
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

// CreateRegistrationEntry stores the given registration entry
func (ds *DataStore) CreateRegistrationEntry(ctx context.Context, entry *common.RegistrationEntry) (*common.RegistrationEntry, error) {
	out, _, err := ds.CreateOrReturnRegistrationEntry(ctx, entry)
	return out, err
}

// CreateOrReturnRegistrationEntry stores the given registration entry. If an
// entry already exists with the same (parentID, spiffeID, selector) tuple,
// that entry is returned instead.
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
			Pagination: &datastore.Pagination{
				PageSize: int32(1),
			},
		},
	})

	if len(records) > 0 {
		return records[0].Object.Entry, true, nil
	}

	if err = ds.validateFederatesWith(ctx, entry.FederatesWith); err != nil {
		return nil, false, err
	}

	entryID, err := createOrReturnEntryID(entry)
	if err != nil {
		return nil, false, err
	}
	entryWithID := *entry
	entryWithID.EntryId = entryID

	if err := ds.entries.Create(ctx, entryObject{Entry: &entryWithID}); err != nil {
		return nil, false, dsErr(err, "failed to create entry")
	}

	if err = ds.createRegistrationEntryEvent(ctx, &datastore.RegistrationEntryEvent{
		EntryID: entryID,
	}); err != nil {
		return nil, false, err
	}

	ret, err := ds.FetchRegistrationEntry(ctx, entryID)
	return ret, false, err
}

// DeleteRegistrationEntry deletes the given registration
func (ds *DataStore) DeleteRegistrationEntry(ctx context.Context, entryID string) (*common.RegistrationEntry, error) {
	r, err := ds.entries.Get(ctx, entryID)
	if err != nil {
		return nil, dsErr(err, "datastore-keyvalue")
	}

	if err := ds.entries.Delete(ctx, entryID); err != nil {
		return nil, dsErr(err, "datastore-keyvalue")
	}

	if ds.createRegistrationEntryEvent(ctx, &datastore.RegistrationEntryEvent{
		EntryID: entryID,
	}); err != nil {
		return nil, err
	}

	return r.Object.Entry, nil
}

// FetchRegistrationEntry fetches an existing registration by entry ID
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

// ListRegistrationEntries lists all registrations (pagination available)
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

// PruneRegistrationEntries takes a registration entry message, and deletes all entries which have expired
// before the date in the message
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

// UpdateRegistrationEntry updates an existing registration entry
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

	if updated.Entry.StoreSvid && !equalSelectorTypes(updated.Entry.Selectors) {
		err := validationError.New("invalid registration entry: selector types must be the same when store SVID is enabled")
		return nil, status.Errorf(codes.InvalidArgument, "%s", err.Error())
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
		if err = ds.validateFederatesWith(ctx, updated.Entry.FederatesWith); err != nil {
			return nil, err
		}
	}
	updated.Entry.RevisionNumber++

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
		err := validationError.New("invalid request: missing registered entry")
		return status.Errorf(codes.InvalidArgument, "%s", err.Error())
	}

	if len(entry.Selectors) == 0 {
		err := validationError.New("invalid registration entry: missing selector list")
		return status.Errorf(codes.InvalidArgument, "%s", err.Error())
	}

	// In case of StoreSvid is set, all entries 'must' be the same type,
	// it is done to avoid users to mix selectors from different platforms in
	// entries with storable SVIDs
	if entry.StoreSvid {
		// Selectors must never be empty
		tpe := entry.Selectors[0].Type
		for _, t := range entry.Selectors {
			if tpe != t.Type {
				err := validationError.New("invalid registration entry: selector types must be the same when store SVID is enabled")
				return status.Errorf(codes.InvalidArgument, "%s", err.Error())
			}
		}
	}

	if len(entry.EntryId) > 255 {
		err := validationError.New("invalid registration entry: entry ID too long")
		return status.Errorf(codes.InvalidArgument, "%s", err.Error())
	}

	for _, e := range entry.EntryId {
		if !unicode.In(e, validEntryIDChars) {
			err := validationError.New("invalid registration entry: entry ID contains invalid characters")
			return status.Errorf(codes.InvalidArgument, "%s", err.Error())
		}
	}

	if len(entry.SpiffeId) == 0 {
		err := validationError.New("invalid registration entry: missing SPIFFE ID")
		return status.Errorf(codes.InvalidArgument, "%s", err.Error())
	}

	if entry.X509SvidTtl < 0 {
		err := validationError.New("invalid registration entry: X509SvidTtl is not set")
		return status.Errorf(codes.InvalidArgument, "%s", err.Error())
	}

	if entry.JwtSvidTtl < 0 {
		err := validationError.New("invalid registration entry: JwtSvidTtl is not set")
		return status.Errorf(codes.InvalidArgument, "%s", err.Error())
	}

	return nil
}

func equalSelectorTypes(selectors []*common.Selector) bool {
	typ := ""
	for _, t := range selectors {
		switch {
		case typ == "":
			typ = t.Type
		case typ != t.Type:
			return false
		}
	}
	return true
}

func (ds *DataStore) validateFederatesWith(ctx context.Context, ids []string) error {
	bundles, _, err := ds.bundles.List(ctx, &datastore.ListBundlesRequest{})
	if err != nil {
		return err
	}

	// make sure all the ids were found
	idset := make(map[string]bool)
	for _, r := range bundles {
		idset[r.Object.Bundle.TrustDomainId] = true
	}

	for _, id := range ids {
		if !idset[id] {
			return fmt.Errorf("unable to find federated bundle %q", id)
		}
	}

	return nil
}

func validateRegistrationEntryForUpdate(entry *common.RegistrationEntry, mask *common.RegistrationEntryMask) error {
	if entry == nil {
		return validationError.New("invalid request: missing registered entry")
	}

	if (mask == nil || mask.Selectors) && len(entry.Selectors) == 0 {
		return validationError.New("invalid registration entry: missing selector list")
	}

	if (mask == nil || mask.SpiffeId) &&
		entry.SpiffeId == "" {
		return validationError.New("invalid registration entry: missing SPIFFE ID")
	}

	if (mask == nil || mask.X509SvidTtl) &&
		(entry.X509SvidTtl < 0) {
		return validationError.New("invalid registration entry: X509SvidTtl is not set")
	}

	if (mask == nil || mask.JwtSvidTtl) &&
		(entry.JwtSvidTtl < 0) {
		return validationError.New("invalid registration entry: JwtSvidTtl is not set")
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
	c.parentID.SetQuery("Object.Entry.ParentId")
	c.spiffeID.SetQuery("Object.Entry.SpiffeId")
	c.selectors.SetQuery("Object.Entry.Selectors")
	c.federatesWith.SetQuery("Object.Entry.FederatesWith")
	c.expiresAt.SetQuery("Object.Entry.EntryExpiry")
	c.hint.SetQuery("Object.Entry.Hint")
	c.downstream.SetQuery("Object.Entry.Downstream")
}

func (c *entryIndex) Get(obj *record.Record[entryObject]) {
	obj.Object.Entry.CreatedAt = roundedInSecondsUnix(obj.Metadata.CreatedAt)
}

func roundedInSecondsUnix(t time.Time) int64 {
	return t.Round(time.Second).Unix()
}

func (c *entryIndex) List(req *listRegistrationEntries) (*keyvalue.ListObject, error) {
	cursor, limit, err := getPaginationParams(req.Pagination)
	if err != nil {
		return nil, err
	}

	if req.BySelectors != nil && len(req.BySelectors.Selectors) == 0 {
		return nil, status.Error(codes.InvalidArgument, "cannot list by empty selector set")
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
