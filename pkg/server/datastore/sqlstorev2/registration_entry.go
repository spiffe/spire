package sqlstorev2

import (
	"context"
	"database/sql"
	"fmt"
	"slices"
	"strconv"
	"time"
	"unicode"

	"github.com/gofrs/uuid/v5"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/pkg/server/datastore/sqlcommon"
	"github.com/spiffe/spire/proto/spire/common"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const (
	maxAdditionalAttributesSize = 65535
)

// entryFetchChunk caps the entry IDs loaded by one statement. Tests lower it
// to cover chunking, so tests in this package must not run in parallel.
var entryFetchChunk = 1000

var validEntryIDChars = &unicode.RangeTable{
	R16: []unicode.Range16{
		{0x002d, 0x002e, 1}, // - | .
		{0x0030, 0x0039, 1}, // [0-9]
		{0x0041, 0x005a, 1}, // [A-Z]
		{0x005f, 0x005f, 1}, // _
		{0x0061, 0x007a, 1}, // [a-z]
	},
	LatinOffset: 5,
}

func (ds *Plugin) CreateRegistrationEntry(ctx context.Context, entry *common.RegistrationEntry) (*common.RegistrationEntry, error) {
	out, _, err := ds.createOrReturnRegistrationEntry(ctx, entry)
	return out, err
}

// CreateOrReturnRegistrationEntry returns the existing entry, and true, when
// one has the same parent ID, SPIFFE ID and selectors.
func (ds *Plugin) CreateOrReturnRegistrationEntry(ctx context.Context, entry *common.RegistrationEntry) (*common.RegistrationEntry, bool, error) {
	return ds.createOrReturnRegistrationEntry(ctx, entry)
}

func (ds *Plugin) createOrReturnRegistrationEntry(ctx context.Context, entry *common.RegistrationEntry) (registrationEntry *common.RegistrationEntry, existing bool, err error) {
	if err = ds.withWriteTx(ctx, func(tx *gorm.DB) (err error) {
		if err = validateRegistrationEntry(entry); err != nil {
			return err
		}
		registrationEntry, err = lookupSimilarEntry(tx, ds.DatabaseType(), entry)
		if err != nil {
			return err
		}
		if registrationEntry != nil {
			existing = true
			return nil
		}
		registrationEntry, err = createRegistrationEntry(tx, entry)
		if err != nil {
			return err
		}
		return createRegistrationEntryEvent(tx, &datastore.RegistrationEntryEvent{EntryID: registrationEntry.EntryId})
	}); err != nil {
		return nil, false, err
	}
	return registrationEntry, existing, nil
}

func (ds *Plugin) FetchRegistrationEntries(ctx context.Context, entryIDs []string) (entries map[string]*common.RegistrationEntry, err error) {
	if err = ds.withReadDB(ctx, datastore.RequireCurrent, func(db *gorm.DB) (err error) {
		entries, err = fetchRegistrationEntries(db, entryIDs)
		return err
	}); err != nil {
		return nil, err
	}
	return entries, nil
}

func (ds *Plugin) CountRegistrationEntries(ctx context.Context, req *datastore.CountRegistrationEntriesRequest) (count int32, err error) {
	if err := validateEntryFilter(nil, req.BySelectors, req.ByFederatesWith); err != nil {
		return 0, err
	}
	if err = ds.withReadDB(ctx, req.DataConsistency, func(db *gorm.DB) (err error) {
		count, err = countRegistrationEntries(db, ds.DatabaseType(), req)
		return err
	}); err != nil {
		return 0, err
	}
	return count, nil
}

func (ds *Plugin) ListRegistrationEntries(ctx context.Context, req *datastore.ListRegistrationEntriesRequest) (resp *datastore.ListRegistrationEntriesResponse, err error) {
	if err := validateEntryFilter(req.Pagination, req.BySelectors, req.ByFederatesWith); err != nil {
		return nil, err
	}
	if err = ds.withReadDB(ctx, req.DataConsistency, func(db *gorm.DB) (err error) {
		resp, err = listRegistrationEntries(db, ds.DatabaseType(), req)
		return err
	}); err != nil {
		return nil, err
	}
	return resp, nil
}

// UpdateRegistrationEntry updates the fields of the given entry selected by
// mask. A nil mask updates every field.
func (ds *Plugin) UpdateRegistrationEntry(ctx context.Context, e *common.RegistrationEntry, mask *common.RegistrationEntryMask) (entry *common.RegistrationEntry, err error) {
	if err = ds.withReadModifyWriteTx(ctx, func(tx *gorm.DB) (err error) {
		entry, err = updateRegistrationEntry(tx, e, mask)
		if err != nil {
			return err
		}
		return createRegistrationEntryEvent(tx, &datastore.RegistrationEntryEvent{EntryID: entry.EntryId})
	}); err != nil {
		return nil, err
	}
	return entry, nil
}

func (ds *Plugin) DeleteRegistrationEntry(ctx context.Context, entryID string) (registrationEntry *common.RegistrationEntry, err error) {
	if err = ds.withWriteTx(ctx, func(tx *gorm.DB) (err error) {
		registrationEntry, err = deleteRegistrationEntry(tx, entryID)
		if err != nil {
			return err
		}
		return createRegistrationEntryEvent(tx, &datastore.RegistrationEntryEvent{EntryID: entryID})
	}); err != nil {
		return nil, err
	}
	return registrationEntry, nil
}

// PruneRegistrationEntries deletes the entries that expired before
// expiresBefore.
func (ds *Plugin) PruneRegistrationEntries(ctx context.Context, expiresBefore time.Time) error {
	return ds.withWriteTx(ctx, func(tx *gorm.DB) error {
		return pruneRegistrationEntries(tx, expiresBefore, ds.log)
	})
}

func (ds *Plugin) ListRegistrationEntryEvents(ctx context.Context, req *datastore.ListRegistrationEntryEventsRequest) (resp *datastore.ListRegistrationEntryEventsResponse, err error) {
	if req.GreaterThanEventID != 0 && req.LessThanEventID != 0 {
		return nil, sqlcommon.NewSQLError("can't set both greater and less than event id")
	}
	if err = ds.withReadDB(ctx, req.DataConsistency, func(db *gorm.DB) (err error) {
		resp, err = listRegistrationEntryEvents(db, req)
		return err
	}); err != nil {
		return nil, err
	}
	return resp, nil
}

func (ds *Plugin) PruneRegistrationEntryEvents(ctx context.Context, olderThan time.Duration) error {
	return ds.withWriteTx(ctx, func(tx *gorm.DB) error {
		return sqlcommon.NewWrappedSQLError(tx.Where("created_at < ?", time.Now().Add(-olderThan)).Delete(&RegisteredEntryEvent{}).Error)
	})
}

func (ds *Plugin) CreateRegistrationEntryEventForTesting(ctx context.Context, event *datastore.RegistrationEntryEvent) error {
	return ds.withWriteTx(ctx, func(tx *gorm.DB) error {
		return createRegistrationEntryEvent(tx, event)
	})
}

func (ds *Plugin) DeleteRegistrationEntryEventForTesting(ctx context.Context, eventID uint) error {
	return ds.withWriteTx(ctx, func(tx *gorm.DB) error {
		return sqlcommon.NewWrappedSQLError(tx.Delete(&RegisteredEntryEvent{ID: eventID}).Error)
	})
}

func (ds *Plugin) FetchRegistrationEntryEvent(ctx context.Context, eventID uint) (event *datastore.RegistrationEntryEvent, err error) {
	if err = ds.withReadDB(ctx, datastore.RequireCurrent, func(db *gorm.DB) error {
		var model RegisteredEntryEvent
		if err := db.Where("id = ?", eventID).Take(&model).Error; err != nil {
			return sqlcommon.NewWrappedSQLError(err)
		}
		event = &datastore.RegistrationEntryEvent{EventID: model.ID, EntryID: model.EntryID}
		return nil
	}); err != nil {
		return nil, err
	}
	return event, nil
}

func createRegistrationEntry(tx *gorm.DB, entry *common.RegistrationEntry) (*common.RegistrationEntry, error) {
	entryID := entry.EntryId
	if entryID == "" {
		u, err := uuid.NewV4()
		if err != nil {
			return nil, err
		}
		entryID = u.String()
	}

	additionalAttributes, err := marshalAndValidateAdditionalAttributes(entry.AdditionalAttributes)
	if err != nil {
		return nil, err
	}

	model := RegisteredEntry{
		EntryID:              entryID,
		SpiffeID:             entry.SpiffeId,
		ParentID:             entry.ParentId,
		TTL:                  entry.X509SvidTtl,
		Admin:                entry.Admin,
		Downstream:           entry.Downstream,
		Expiry:               entry.EntryExpiry,
		StoreSvid:            entry.StoreSvid,
		JWTSvidTTL:           entry.JwtSvidTtl,
		Hint:                 entry.Hint,
		AdditionalAttributes: additionalAttributes,
	}
	// wit_svid_ttl is not written until SPIRE 1.17.0, so servers that predate
	// the column can share the database.
	if err := tx.Omit("wit_svid_ttl").Create(&model).Error; err != nil {
		return nil, sqlcommon.NewWrappedSQLError(err)
	}

	federatesWith, err := setEntryChildren(tx, model.ID, entry, true, true, true)
	if err != nil {
		return nil, err
	}

	return &common.RegistrationEntry{
		EntryId:              model.EntryID,
		Selectors:            entry.Selectors,
		SpiffeId:             model.SpiffeID,
		ParentId:             model.ParentID,
		X509SvidTtl:          model.TTL,
		FederatesWith:        federatesWith,
		Admin:                model.Admin,
		Downstream:           model.Downstream,
		EntryExpiry:          model.Expiry,
		DnsNames:             entry.DnsNames,
		StoreSvid:            model.StoreSvid,
		JwtSvidTtl:           model.JWTSvidTTL,
		Hint:                 model.Hint,
		AdditionalAttributes: storedAdditionalAttributes(entry.AdditionalAttributes, additionalAttributes),
		CreatedAt:            roundedInSecondsUnix(model.CreatedAt),
	}, nil
}

// setEntryChildren writes the selected child rows of entry, which must have
// none of those rows, and returns the trust domains it federates with.
func setEntryChildren(tx *gorm.DB, id uint, entry *common.RegistrationEntry, selectors, dnsNames, federatesWith bool) ([]string, error) {
	if selectors && len(entry.Selectors) > 0 {
		rows := make([]Selector, 0, len(entry.Selectors))
		for _, s := range entry.Selectors {
			rows = append(rows, Selector{RegisteredEntryID: id, Type: s.Type, Value: s.Value})
		}
		if err := tx.Create(&rows).Error; err != nil {
			return nil, sqlcommon.NewWrappedSQLError(err)
		}
	}
	if dnsNames && len(entry.DnsNames) > 0 {
		rows := make([]DNSName, 0, len(entry.DnsNames))
		for _, d := range entry.DnsNames {
			rows = append(rows, DNSName{RegisteredEntryID: id, Value: d})
		}
		if err := tx.Create(&rows).Error; err != nil {
			return nil, sqlcommon.NewWrappedSQLError(err)
		}
	}
	if !federatesWith || len(entry.FederatesWith) == 0 {
		return nil, nil
	}

	var bundles []Bundle
	if err := tx.Select("id", "trust_domain").Where("trust_domain IN ?", entry.FederatesWith).Order("id").Find(&bundles).Error; err != nil {
		return nil, sqlcommon.NewWrappedSQLError(err)
	}
	found := make(map[string]bool, len(bundles))
	for _, b := range bundles {
		found[b.TrustDomain] = true
	}
	for _, td := range entry.FederatesWith {
		if !found[td] {
			return nil, fmt.Errorf("unable to find federated bundle %q", td)
		}
	}

	rows := make([]FederatedRegistrationEntry, 0, len(bundles))
	trustDomains := make([]string, 0, len(bundles))
	for _, b := range bundles {
		rows = append(rows, FederatedRegistrationEntry{BundleID: b.ID, RegisteredEntryID: id})
		trustDomains = append(trustDomains, b.TrustDomain)
	}
	if err := tx.Create(&rows).Error; err != nil {
		return nil, sqlcommon.NewWrappedSQLError(err)
	}
	return trustDomains, nil
}

// lookupSimilarEntry returns an entry with the parent ID, SPIFFE ID and
// selectors of entry, or nil if there is none.
func lookupSimilarEntry(tx *gorm.DB, dbType string, entry *common.RegistrationEntry) (*common.RegistrationEntry, error) {
	resp, err := listRegistrationEntries(tx, dbType, &datastore.ListRegistrationEntriesRequest{
		BySpiffeID:  entry.SpiffeId,
		ByParentID:  entry.ParentId,
		BySelectors: &datastore.BySelectors{Match: datastore.Exact, Selectors: entry.Selectors},
		Pagination:  &datastore.Pagination{PageSize: 1},
	})
	if err != nil || len(resp.Entries) == 0 {
		return nil, err
	}
	return resp.Entries[0], nil
}

func fetchRegistrationEntries(db *gorm.DB, entryIDs []string) (map[string]*common.RegistrationEntry, error) {
	entries := make(map[string]*common.RegistrationEntry, len(entryIDs))
	for chunk := range chunkSlice(entryIDs, entryFetchChunk) {
		if len(chunk) <= 10 {
			// Small enough for one statement; larger ones get a parallel plan
			// on PostgreSQL, whose worker startup costs more than a round trip.
			list, _, err := loadEntries(db, true, "%[1]s IN (SELECT id FROM registered_entries WHERE entry_id IN ?)", padIDs(chunk))
			if err != nil {
				return nil, err
			}
			for _, e := range list {
				entries[e.EntryId] = e
			}
			continue
		}
		var ids []uint
		if err := db.Session(&gorm.Session{PrepareStmt: true}).Model(&RegisteredEntry{}).
			Where("entry_id IN ?", padIDs(chunk)).Order("id").Pluck("id", &ids).Error; err != nil {
			return nil, sqlcommon.NewWrappedSQLError(err)
		}
		list, err := loadEntriesByID(db, ids)
		if err != nil {
			return nil, err
		}
		for _, e := range list {
			entries[e.EntryId] = e
		}
	}
	return entries, nil
}

// entryFilter holds the entry filters shared by list and count requests.
type entryFilter struct {
	byParentID      string
	bySpiffeID      string
	byHint          string
	byDownstream    *bool
	bySelectors     *datastore.BySelectors
	byFederatesWith *datastore.ByFederatesWith
	afterID         uint64 // page token; 0 for none
}

func filterEntries(query *gorm.DB, dbType string, f entryFilter) *gorm.DB {
	if f.byParentID != "" {
		query = query.Where("registered_entries.parent_id = ?", f.byParentID)
	}
	if f.bySpiffeID != "" {
		query = query.Where("registered_entries.spiffe_id = ?", f.bySpiffeID)
	}
	if f.byHint != "" {
		query = query.Where("registered_entries.hint = ?", f.byHint)
	}
	// A false ByDownstream does not filter.
	if f.byDownstream != nil && *f.byDownstream {
		query = query.Where("registered_entries.downstream = ?", true)
	}
	if f.bySelectors != nil {
		match := matchEachIn
		if f.byParentID != "" || f.bySpiffeID != "" || f.byHint != "" {
			match = matchEachExists
		}
		query = filterBySelectors(query, dbType, f.bySelectors, "selectors", "registered_entry_id", "registered_entries.id", match)
	}
	if f.byFederatesWith != nil && len(f.byFederatesWith.TrustDomains) > 0 {
		query = filterByFederatesWith(query, f.byFederatesWith, f.afterID)
	}
	if f.afterID > 0 {
		query = query.Where("registered_entries.id > ?", f.afterID)
	}
	return query
}

// filterByFederatesWith restricts query to entries whose trust domains match
// by, as for selectors. afterID (the page token) also bounds the subqueries,
// or PostgreSQL merge-joins them from the first entry on every page.
func filterByFederatesWith(query *gorm.DB, by *datastore.ByFederatesWith, afterID uint64) *gorm.DB {
	trustDomains := uniqueStrings(by.TrustDomains)
	federated := func(alias string) *gorm.DB {
		q := query.Session(&gorm.Session{NewDB: true}).Table("federated_registration_entries AS " + alias).
			Joins("JOIN bundles AS " + alias + "b ON " + alias + "b.id = " + alias + ".bundle_id")
		if afterID > 0 {
			q = q.Where(alias+".registered_entry_id > ?", afterID)
		}
		return q
	}
	matching := federated("f").Select("f.registered_entry_id").Where("fb.trust_domain IN ?", trustDomains)
	hasAll := federated("f").Select("f.registered_entry_id").Where("fb.trust_domain IN ?", trustDomains).
		Group("f.registered_entry_id").Having("COUNT(*) = ?", len(trustDomains))
	outside := federated("o").Select("1").Where("o.registered_entry_id = registered_entries.id").
		Where("ob.trust_domain NOT IN ?", trustDomains)
	join := func(q, sub *gorm.DB) *gorm.DB {
		return q.Joins("JOIN (?) AS fm ON fm.registered_entry_id = registered_entries.id", sub)
	}

	switch by.Match {
	case datastore.MatchAny:
		return join(query, matching.Distinct())
	case datastore.Superset:
		return join(query, hasAll)
	case datastore.Subset:
		return query.Where("registered_entries.id IN (?)", matching).Where("NOT EXISTS (?)", outside)
	default: // datastore.Exact; validateEntryFilter rejects anything else.
		return join(query, hasAll).Where("NOT EXISTS (?)", outside)
	}
}

func validateEntryFilter(p *datastore.Pagination, bySelectors *datastore.BySelectors, byFederatesWith *datastore.ByFederatesWith) error {
	if p != nil && p.PageSize == 0 {
		return status.Error(codes.InvalidArgument, "cannot paginate with pagesize = 0")
	}
	if bySelectors != nil && len(bySelectors.Selectors) == 0 {
		return status.Error(codes.InvalidArgument, "cannot list by empty selector set")
	}
	if err := validateSelectorMatch(bySelectors); err != nil {
		return err
	}
	if byFederatesWith == nil || len(byFederatesWith.TrustDomains) == 0 {
		return nil
	}
	switch byFederatesWith.Match {
	case datastore.MatchAny, datastore.Superset, datastore.Subset, datastore.Exact:
		return nil
	default:
		return status.Errorf(codes.InvalidArgument, "unhandled federates with match behavior %d", byFederatesWith.Match)
	}
}

func countRegistrationEntries(db *gorm.DB, dbType string, req *datastore.CountRegistrationEntriesRequest) (int32, error) {
	query := filterEntries(db.Model(&RegisteredEntry{}), dbType, entryFilter{
		byParentID:      req.ByParentID,
		bySpiffeID:      req.BySpiffeID,
		byHint:          req.ByHint,
		byDownstream:    req.ByDownstream,
		bySelectors:     req.BySelectors,
		byFederatesWith: req.ByFederatesWith,
	})
	var count int64
	if err := query.Count(&count).Error; err != nil {
		return 0, sqlcommon.NewWrappedSQLError(err)
	}
	return util.CheckedCast[int32](count)
}

// listRegistrationEntries lists the entries matching req, which must pass
// validateEntryFilter.
func listRegistrationEntries(db *gorm.DB, dbType string, req *datastore.ListRegistrationEntriesRequest) (*datastore.ListRegistrationEntriesResponse, error) {
	equalityOnly := req.BySelectors == nil && (req.ByFederatesWith == nil || len(req.ByFederatesWith.TrustDomains) == 0)
	filtered := req.ByParentID != "" || req.BySpiffeID != "" || req.ByHint != "" ||
		(req.ByDownstream != nil && *req.ByDownstream) || req.BySelectors != nil ||
		(req.ByFederatesWith != nil && len(req.ByFederatesWith.TrustDomains) > 0)

	var afterID uint64
	if p := req.Pagination; p != nil && p.Token != "" {
		var err error
		if afterID, err = parsePaginationToken(p.Token, dbType); err != nil {
			return nil, err
		}
	}
	query := filterEntries(db.Session(&gorm.Session{NewDB: true}).Model(&RegisteredEntry{}), dbType, entryFilter{
		byParentID:      req.ByParentID,
		bySpiffeID:      req.BySpiffeID,
		byHint:          req.ByHint,
		byDownstream:    req.ByDownstream,
		bySelectors:     req.BySelectors,
		byFederatesWith: req.ByFederatesWith,
		afterID:         afterID,
	}).Select("registered_entries.id").Order("registered_entries.id")
	if p := req.Pagination; p != nil {
		query = query.Limit(int(p.PageSize))
	}

	var (
		entries []*common.RegistrationEntry
		lastID  uint64
		err     error
	)
	switch {
	case !filtered && req.Pagination == nil:
		entries, lastID, err = loadEntries(db, true, "%[1]s >= 0")
	case !filtered:
		// The page is an id range, read from each table with an index range
		// scan. The token is always bound so the statement text is fixed.
		entries, lastID, err = loadEntries(db, true, "%[1]s > ? AND %[1]s <= (SELECT MAX(id) FROM (SELECT id FROM registered_entries WHERE id > ? ORDER BY id LIMIT ?) AS p)",
			afterID, afterID, int(req.Pagination.PageSize))
	default:
		// Ids first: the filter repeated in each branch gets a parallel plan on
		// PostgreSQL, slower than a second round trip. Selector filter plans
		// depend on the values, so only equality filters are prepared.
		if equalityOnly {
			query = query.Session(&gorm.Session{PrepareStmt: true})
		}
		var ids []uint
		if err := query.Pluck("registered_entries.id", &ids).Error; err != nil {
			return nil, sqlcommon.NewWrappedSQLError(err)
		}
		entries, err = loadEntriesByID(db, ids)
		if len(ids) > 0 {
			// An entry deleted since the ids were read must not end the paging.
			lastID = uint64(ids[len(ids)-1])
		}
	}
	if err != nil {
		return nil, err
	}

	resp := &datastore.ListRegistrationEntriesResponse{Entries: entries}
	if p := req.Pagination; p != nil {
		resp.Pagination = &datastore.Pagination{PageSize: p.PageSize}
		if lastID != 0 {
			resp.Pagination.Token = strconv.FormatUint(lastID, 10)
		}
	}
	return resp, nil
}

// entryColumns are the registered_entries columns an entry is built from, in
// the order scanEntryRows expects after the row kind columns.
const entryColumns = "entry_id, spiffe_id, parent_id, ttl, admin, downstream, expiry, store_svid, hint, created_at, revision_number, jwt_svid_ttl, additional_attributes"

// entryRowsQuery reads entries and child rows as (entry id, kind, child id, s1,
// s2, entry columns): kind 0 the entry, 1 a selector (s1, s2), 2 a DNS name and
// 3 a trust domain (s1). The entry branch types the others' NULLs on PostgreSQL.
const entryRowsQuery = `SELECT id AS e_id, 0 AS kind, 0 AS child_id, '' AS s1, '' AS s2, ` + entryColumns + ` FROM registered_entries WHERE %s
UNION ALL SELECT registered_entry_id, 1, id, type, value, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL FROM selectors WHERE %s
UNION ALL SELECT registered_entry_id, 2, id, value, '', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL FROM dns_names WHERE %s
UNION ALL SELECT f.registered_entry_id, 3, b.id, b.trust_domain, '', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL FROM federated_registration_entries f JOIN bundles b ON b.id = f.bundle_id WHERE %s
ORDER BY e_id, kind, child_id`

// loadEntries returns, in id order, the entries whose id matches cond (with
// %[1]s for the id column) and the last entry's id. prepare suits fixed-text
// queries with stable plans: PostgreSQL then skips planning, often the larger cost.
func loadEntries(db *gorm.DB, prepare bool, cond string, args ...any) ([]*common.RegistrationEntry, uint64, error) {
	allArgs := make([]any, 0, 4*len(args))
	for range 4 {
		allArgs = append(allArgs, args...)
	}
	query := fmt.Sprintf(entryRowsQuery, fmt.Sprintf(cond, "id"), fmt.Sprintf(cond, "registered_entry_id"),
		fmt.Sprintf(cond, "registered_entry_id"), fmt.Sprintf(cond, "f.registered_entry_id"))
	if prepare {
		db = db.Session(&gorm.Session{PrepareStmt: true})
	}
	rows, err := db.Raw(query, allArgs...).Rows()
	if err != nil {
		return nil, 0, sqlcommon.NewWrappedSQLError(err)
	}
	defer rows.Close()
	return scanEntryRows(rows)
}

// loadEntriesByID returns the entries with the given ids in id order, sorting
// ids in place.
func loadEntriesByID(db *gorm.DB, ids []uint) ([]*common.RegistrationEntry, error) {
	slices.Sort(ids)
	var entries []*common.RegistrationEntry
	for chunk := range chunkSlice(ids, entryFetchChunk) {
		list, _, err := loadEntries(db, true, "%[1]s IN ?", padIDs(chunk))
		if err != nil {
			return nil, err
		}
		entries = append(entries, list...)
	}
	return entries, nil
}

func scanEntryRows(rows *sql.Rows) ([]*common.RegistrationEntry, uint64, error) {
	var (
		entries []*common.RegistrationEntry
		entry   *common.RegistrationEntry
		lastID  uint64
	)
	for rows.Next() {
		var (
			eID                                       uint64
			kind                                      int
			childID                                   int64
			s1, s2, entryID, spiffeID, parentID, hint sql.NullString
			ttl, expiry, revision, jwtTTL             sql.NullInt64
			admin, downstream, storeSvid              sql.NullBool
			createdAt                                 sql.NullTime
			additionalAttributes                      []byte
		)
		if err := rows.Scan(&eID, &kind, &childID, &s1, &s2, &entryID, &spiffeID, &parentID, &ttl, &admin, &downstream, &expiry, &storeSvid, &hint, &createdAt, &revision, &jwtTTL, &additionalAttributes); err != nil {
			return nil, 0, sqlcommon.NewWrappedSQLError(err)
		}

		if kind == 0 {
			lastID = eID
			entry = &common.RegistrationEntry{
				EntryId:        entryID.String,
				SpiffeId:       spiffeID.String,
				ParentId:       parentID.String,
				Admin:          admin.Bool,
				Downstream:     downstream.Bool,
				EntryExpiry:    expiry.Int64,
				StoreSvid:      storeSvid.Bool,
				Hint:           hint.String,
				RevisionNumber: revision.Int64,
			}
			var err error
			if entry.X509SvidTtl, err = util.CheckedCast[int32](ttl.Int64); err != nil {
				return nil, 0, sqlcommon.NewSQLError("invalid value for X.509 SVID TTL: %s", err)
			}
			if entry.JwtSvidTtl, err = util.CheckedCast[int32](jwtTTL.Int64); err != nil {
				return nil, 0, sqlcommon.NewSQLError("invalid value for JWT SVID TTL: %s", err)
			}
			if createdAt.Valid {
				entry.CreatedAt = roundedInSecondsUnix(createdAt.Time)
			}
			if len(additionalAttributes) > 0 {
				entry.AdditionalAttributes = &common.RegistrationEntry_AdditionalAttributes{}
				if err := proto.Unmarshal(additionalAttributes, entry.AdditionalAttributes); err != nil {
					return nil, 0, sqlcommon.NewSQLError("could not parse cache hint flags: %s", err)
				}
			}
			entries = append(entries, entry)
			continue
		}
		// Child rows of a deleted entry (see #1191) have no entry row.
		if entry == nil || eID != lastID {
			continue
		}
		switch kind {
		case 1:
			entry.Selectors = append(entry.Selectors, &common.Selector{Type: s1.String, Value: s2.String})
		case 2:
			entry.DnsNames = append(entry.DnsNames, s1.String)
		case 3:
			entry.FederatesWith = append(entry.FederatesWith, s1.String)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, 0, sqlcommon.NewWrappedSQLError(err)
	}
	return entries, lastID, nil
}

func updateRegistrationEntry(tx *gorm.DB, e *common.RegistrationEntry, mask *common.RegistrationEntryMask) (*common.RegistrationEntry, error) {
	if err := validateRegistrationEntryForUpdate(e, mask); err != nil {
		return nil, err
	}

	var model RegisteredEntry
	if err := tx.Where("entry_id = ?", e.EntryId).Take(&model).Error; err != nil {
		return nil, sqlcommon.NewWrappedSQLError(err)
	}

	all := mask == nil
	if all || mask.StoreSvid {
		model.StoreSvid = e.StoreSvid
	}
	// Selector types are only checked when the selectors change.
	if (all || mask.Selectors) && model.StoreSvid && !equalSelectorTypes(e.Selectors) {
		return nil, sqlcommon.NewValidationError("invalid registration entry: selector types must be the same when store SVID is enabled")
	}
	if all || mask.SpiffeId {
		model.SpiffeID = e.SpiffeId
	}
	if all || mask.ParentId {
		model.ParentID = e.ParentId
	}
	if all || mask.X509SvidTtl {
		model.TTL = e.X509SvidTtl
	}
	if all || mask.Admin {
		model.Admin = e.Admin
	}
	if all || mask.Downstream {
		model.Downstream = e.Downstream
	}
	if all || mask.EntryExpiry {
		model.Expiry = e.EntryExpiry
	}
	if all || mask.JwtSvidTtl {
		model.JWTSvidTTL = e.JwtSvidTtl
	}
	if all || mask.Hint {
		model.Hint = e.Hint
	}
	if all || mask.AdditionalAttributes {
		additionalAttributes, err := marshalAndValidateAdditionalAttributes(e.AdditionalAttributes)
		if err != nil {
			return nil, err
		}
		model.AdditionalAttributes = additionalAttributes
	}
	model.RevisionNumber++

	if err := tx.Model(&model).Select("store_svid", "spiffe_id", "parent_id", "ttl", "admin", "downstream", "expiry", "jwt_svid_ttl", "hint", "additional_attributes", "revision_number", "updated_at").
		Omit(clause.Associations).Updates(&model).Error; err != nil {
		return nil, sqlcommon.NewWrappedSQLError(err)
	}

	setSelectors, setDNSNames, setFederatesWith := all || mask.Selectors, all || mask.DnsNames, all || mask.FederatesWith
	if err := deleteEntryChildren(tx, []uint{model.ID}, setSelectors, setDNSNames, setFederatesWith); err != nil {
		return nil, err
	}
	if _, err := setEntryChildren(tx, model.ID, e, setSelectors, setDNSNames, setFederatesWith); err != nil {
		return nil, err
	}

	entries, _, err := loadEntries(tx, true, "%[1]s = ?", model.ID)
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, sqlcommon.NewWrappedSQLError(gorm.ErrRecordNotFound)
	}
	return entries[0], nil
}

// deleteEntryChildren deletes the selected child rows of the given entries.
func deleteEntryChildren(tx *gorm.DB, ids []uint, selectors, dnsNames, federatesWith bool) error {
	if selectors {
		if err := tx.Where("registered_entry_id IN ?", ids).Delete(&Selector{}).Error; err != nil {
			return sqlcommon.NewWrappedSQLError(err)
		}
	}
	if dnsNames {
		if err := tx.Where("registered_entry_id IN ?", ids).Delete(&DNSName{}).Error; err != nil {
			return sqlcommon.NewWrappedSQLError(err)
		}
	}
	if federatesWith {
		if err := tx.Where("registered_entry_id IN ?", ids).Delete(&FederatedRegistrationEntry{}).Error; err != nil {
			return sqlcommon.NewWrappedSQLError(err)
		}
	}
	return nil
}

func deleteRegistrationEntry(tx *gorm.DB, entryID string) (*common.RegistrationEntry, error) {
	var model RegisteredEntry
	if err := tx.Select("id").Where("entry_id = ?", entryID).Take(&model).Error; err != nil {
		return nil, sqlcommon.NewWrappedSQLError(err)
	}
	entries, _, err := loadEntries(tx, true, "%[1]s = ?", model.ID)
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, sqlcommon.NewWrappedSQLError(gorm.ErrRecordNotFound)
	}
	if err := deleteEntries(tx, []uint{model.ID}); err != nil {
		return nil, err
	}
	return entries[0], nil
}

// deleteEntries deletes the given entries and their child rows.
func deleteEntries(tx *gorm.DB, ids []uint) error {
	if err := deleteEntryChildren(tx, ids, true, true, true); err != nil {
		return err
	}
	if err := tx.Where("id IN ?", ids).Delete(&RegisteredEntry{}).Error; err != nil {
		return sqlcommon.NewWrappedSQLError(err)
	}
	return nil
}

func pruneRegistrationEntries(tx *gorm.DB, expiresBefore time.Time, log logrus.FieldLogger) error {
	var expired []RegisteredEntry
	if err := tx.Select("id", "entry_id", "spiffe_id", "parent_id").Where("expiry != 0").Where("expiry < ?", expiresBefore.Unix()).Find(&expired).Error; err != nil {
		return sqlcommon.NewWrappedSQLError(err)
	}
	for chunk := range chunkSlice(expired, entryFetchChunk) {
		ids := make([]uint, 0, len(chunk))
		events := make([]RegisteredEntryEvent, 0, len(chunk))
		for _, e := range chunk {
			ids = append(ids, e.ID)
			events = append(events, RegisteredEntryEvent{EntryID: e.EntryID})
		}
		if err := deleteEntries(tx, ids); err != nil {
			return err
		}
		if err := tx.Create(&events).Error; err != nil {
			return sqlcommon.NewWrappedSQLError(err)
		}
	}
	for _, e := range expired {
		log.WithFields(logrus.Fields{
			telemetry.SPIFFEID:       e.SpiffeID,
			telemetry.ParentID:       e.ParentID,
			telemetry.RegistrationID: e.EntryID,
		}).Info("Pruned an expired registration")
	}
	return nil
}

func createRegistrationEntryEvent(tx *gorm.DB, event *datastore.RegistrationEntryEvent) error {
	if err := tx.Create(&RegisteredEntryEvent{ID: event.EventID, EntryID: event.EntryID}).Error; err != nil {
		return sqlcommon.NewWrappedSQLError(err)
	}
	return nil
}

func listRegistrationEntryEvents(db *gorm.DB, req *datastore.ListRegistrationEntryEventsRequest) (*datastore.ListRegistrationEntryEventsResponse, error) {
	query := db.Model(&RegisteredEntryEvent{}).Select("id", "entry_id").Order("id")
	if req.GreaterThanEventID != 0 {
		query = query.Where("id > ?", req.GreaterThanEventID)
	}
	if req.LessThanEventID != 0 {
		query = query.Where("id < ?", req.LessThanEventID)
	}
	var events []RegisteredEntryEvent
	if err := query.Find(&events).Error; err != nil {
		return nil, sqlcommon.NewWrappedSQLError(err)
	}
	resp := &datastore.ListRegistrationEntryEventsResponse{Events: make([]datastore.RegistrationEntryEvent, len(events))}
	for i, e := range events {
		resp.Events[i] = datastore.RegistrationEntryEvent{EventID: e.ID, EntryID: e.EntryID}
	}
	return resp, nil
}

func validateRegistrationEntry(entry *common.RegistrationEntry) error {
	if entry == nil {
		return sqlcommon.NewValidationError("invalid request: missing registered entry")
	}
	if len(entry.Selectors) == 0 {
		return sqlcommon.NewValidationError("invalid registration entry: missing selector list")
	}
	// Storable SVIDs need selectors from a single platform.
	if entry.StoreSvid {
		if entry.AdditionalAttributes.GetDisableX509SvidPrefetch() {
			return sqlcommon.NewValidationError("specifying cache behaviour is incompatible with storable SVIDs")
		}
		if !equalSelectorTypes(entry.Selectors) {
			return sqlcommon.NewValidationError("invalid registration entry: selector types must be the same when store SVID is enabled")
		}
	}
	if len(entry.EntryId) > 255 {
		return sqlcommon.NewValidationError("invalid registration entry: entry ID too long")
	}
	for _, e := range entry.EntryId {
		if !unicode.In(e, validEntryIDChars) {
			return sqlcommon.NewValidationError("invalid registration entry: entry ID contains invalid characters")
		}
	}
	if len(entry.SpiffeId) == 0 {
		return sqlcommon.NewValidationError("invalid registration entry: missing SPIFFE ID")
	}
	if entry.X509SvidTtl < 0 {
		return sqlcommon.NewValidationError("invalid registration entry: X509SvidTtl must not be negative")
	}
	if entry.JwtSvidTtl < 0 {
		return sqlcommon.NewValidationError("invalid registration entry: JwtSvidTtl must not be negative")
	}
	if entry.WitSvidTtl < 0 {
		return sqlcommon.NewValidationError("invalid registration entry: WitSvidTtl must not be negative")
	}
	return nil
}

func validateRegistrationEntryForUpdate(entry *common.RegistrationEntry, mask *common.RegistrationEntryMask) error {
	if entry == nil {
		return sqlcommon.NewValidationError("invalid request: missing registered entry")
	}
	if (mask == nil || mask.Selectors) && len(entry.Selectors) == 0 {
		return sqlcommon.NewValidationError("invalid registration entry: missing selector list")
	}
	if (mask == nil || mask.SpiffeId) && entry.SpiffeId == "" {
		return sqlcommon.NewValidationError("invalid registration entry: missing SPIFFE ID")
	}
	if (mask == nil || mask.X509SvidTtl) && entry.X509SvidTtl < 0 {
		return sqlcommon.NewValidationError("invalid registration entry: X509SvidTtl must not be negative")
	}
	if (mask == nil || mask.JwtSvidTtl) && entry.JwtSvidTtl < 0 {
		return sqlcommon.NewValidationError("invalid registration entry: JwtSvidTtl must not be negative")
	}
	if (mask == nil || mask.WitSvidTtl) && entry.WitSvidTtl < 0 {
		return sqlcommon.NewValidationError("invalid registration entry: WitSvidTtl must not be negative")
	}
	return nil
}

func equalSelectorTypes(selectors []*common.Selector) bool {
	for _, s := range selectors {
		if s.Type != selectors[0].Type {
			return false
		}
	}
	return true
}

func marshalAndValidateAdditionalAttributes(attrs *common.RegistrationEntry_AdditionalAttributes) ([]byte, error) {
	if attrs == nil {
		return nil, nil
	}
	data, err := proto.Marshal(attrs)
	if err != nil {
		return nil, sqlcommon.NewValidationError("invalid additional attributes: %s", err)
	}
	if len(data) > maxAdditionalAttributesSize {
		return nil, sqlcommon.NewValidationError("invalid registration entry: additional attributes size exceeds the maximum allowed size of %d bytes", maxAdditionalAttributesSize)
	}
	return data, nil
}

// storedAdditionalAttributes returns attrs as a read would after storing
// data, its encoding: nil when that is empty.
func storedAdditionalAttributes(attrs *common.RegistrationEntry_AdditionalAttributes, data []byte) *common.RegistrationEntry_AdditionalAttributes {
	if len(data) == 0 {
		return nil
	}
	return proto.CloneOf(attrs)
}

// roundedInSecondsUnix avoids differences from databases that keep sub-second
// precision.
func roundedInSecondsUnix(t time.Time) int64 {
	return t.Round(time.Second).Unix()
}

func uniqueStrings(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	return out
}

// padIDs pads ids to the next of a few fixed lengths by repeating the last
// one, so IN lists produce few distinct prepared statements.
func padIDs[T any](ids []T) []T {
	if len(ids) == 0 {
		return ids
	}
	for _, n := range []int{1, 10, 50, 100, 250, 500, entryFetchChunk} {
		if len(ids) <= n {
			padded := make([]T, n)
			copy(padded, ids)
			for i := len(ids); i < n; i++ {
				padded[i] = ids[len(ids)-1]
			}
			return padded
		}
	}
	return ids
}

// chunkSlice yields s in consecutive chunks of at most n elements.
func chunkSlice[T any](s []T, n int) func(func([]T) bool) {
	return func(yield func([]T) bool) {
		for len(s) > 0 {
			end := min(n, len(s))
			if !yield(s[:end]) {
				return
			}
			s = s[end:]
		}
	}
}
