package cassandra

import (
	"context"
	"encoding/base64"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"
	"unicode"

	gocql "github.com/apache/cassandra-gocql-driver/v2"
	"github.com/gogo/status"
	"github.com/sirupsen/logrus"
	datastorev1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/datastore/v1alpha1"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/server/datastore/cassandra/qb"
	"google.golang.org/grpc/codes"
)

func (p *Plugin) CountRegistrationEntries(ctx context.Context, req *datastorev1.CountRegistrationEntriesRequest) (*datastorev1.CountRegistrationEntriesResponse, error) {
	args := []any{}
	fields := []string{}
	operators := []string{}
	if len(req.ByParentId) > 0 {
		args = append(args, req.ByParentId)
		fields = append(fields, "parent_id")
		operators = append(operators, "=")
	}

	if len(req.BySpiffeId) > 0 {
		args = append(args, req.BySpiffeId)
		fields = append(fields, "spiffe_id")
		operators = append(operators, "=")
	}

	if req.FilterByDownstream {
		args = append(args, req.DownstreamValue)
		fields = append(fields, "downstream")
		operators = append(operators, "=")
	}

	if req.ByFederatesWith != nil && len(req.ByFederatesWith.FederatesWith) > 0 {
		args = append(args, req.ByFederatesWith.FederatesWith)
		fields = append(fields, "federated_trust_domains")
		operators = append(operators, "CONTAINS")
	}

	if len(req.ByHint) > 0 {
		args = append(args, req.ByHint)
		fields = append(fields, "hint")
		operators = append(operators, "=")
	}

	if req.BySelectors != nil {
		// TODO(tjons): implement selector-based counting
		return &datastorev1.CountRegistrationEntriesResponse{
			Count: 0,
		}, nil
	}

	b := strings.Builder{}
	b.WriteString("SELECT DISTINCT entry_id, COUNT(*) FROM registered_entries")
	if len(fields) > 0 {
		b.WriteString(" WHERE ")
		for i, field := range fields {
			if i > 0 {
				b.WriteString(" AND ")
			}
			b.WriteString(field)
			b.WriteString(" ")
			b.WriteString(operators[i])
			b.WriteString(" ?")
		}
	}

	query := b.String()
	cqlQuery := p.db.session.Query(query, args...)
	cqlQuery.Consistency(p.db.cfg.ReadConsistency)

	var (
		count    int32
		dontCare string
	)
	if err := cqlQuery.ScanContext(ctx, &dontCare, &count); err != nil {
		return nil, newWrappedCassandraError(err)
	}

	return &datastorev1.CountRegistrationEntriesResponse{
		Count: count,
	}, nil
}

// TODO(tjons): should this really be there with no validation? is this effectively unused?
func (p *Plugin) CreateRegistrationEntry(ctx context.Context, req *datastorev1.CreateRegistrationEntryRequest) (*datastorev1.CreateRegistrationEntryResponse, error) {
	if req.GetEntry() == nil {
		return nil, newValidationError("invalid request: missing registration entry")
	}

	if err := validateRegistrationEntry(req.GetEntry()); err != nil {
		return nil, err
	}

	if req.GetEntry().FederatesWith != nil {
		bundles, err := p.ListBundles(ctx, &datastorev1.ListBundlesRequest{})
		if err != nil {
			return nil, newWrappedCassandraError(err)
		}

		ftds := make(map[string]bool, len(req.GetEntry().FederatesWith))
		for _, ftd := range req.GetEntry().FederatesWith {
			ftds[ftd] = false
		}

		for _, b := range bundles.Bundles {
			if _, ok := ftds[b.TrustDomainId]; ok {
				ftds[b.TrustDomainId] = true
			}
		}

		for ftd, found := range ftds {
			if !found {
				return nil, fmt.Errorf("unable to find federated bundle %q", ftd)
			}
		}
	}

	newEntry, err := p.createRegistrationEntry(ctx, req.GetEntry())
	if err != nil {
		return nil, err
	}

	err = p.createRegistrationEntryEvent(ctx, &datastorev1.RegistrationEntryEvent{
		EntryId: newEntry.EntryId,
	})

	return &datastorev1.CreateRegistrationEntryResponse{
		Entry: newEntry,
	}, err
}

func (p *Plugin) createRegistrationEntry(ctx context.Context, entry *datastorev1.RegistrationEntry) (*datastorev1.RegistrationEntry, error) {
	var entryID string

	if len(entry.EntryId) > 0 {
		entryID = entry.EntryId
	} else {
		uuid, err := gocql.RandomUUID()
		if err != nil {
			return nil, newWrappedCassandraError(err)
		}
		entryID = uuid.String()
	}

	entry.EntryId = entryID
	entry.CreatedAt = time.Now().Unix()
	entry.UpdatedAt = entry.UpdatedAt

	b := p.db.session.Batch(gocql.LoggedBatch).Consistency(p.db.cfg.WriteConsistency)

	indexes := buildIndexesForRegistrationEntry(entry)

	createEntryQuery := `
		INSERT INTO registered_entries (
			created_at,
			updated_at,
			entry_id,
			spiffe_id,
			parent_id,
			admin,
			downstream,
			ttl,
			expiry,
			revision_number,
			store_svid,
			hint,
			jwt_svid_ttl,
			dns_names,
			federated_trust_domains,
			selector_types,
			selector_values,
			index_terms,
			selector_type_value_full,
			federated_trust_domains_full,
			unrolled_selector_type_val,
			unrolled_ftd
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	selectorTypes := make([]string, 0, len(entry.Selectors))
	selectorValues := make([]string, 0, len(entry.Selectors))
	selectorTypeValueFull := make([]string, 0, len(entry.Selectors))

	for _, sl := range entry.Selectors {
		selectorTypes = append(selectorTypes, sl.Type)
		selectorValues = append(selectorValues, sl.Value)
		selectorTypeValueFull = append(selectorTypeValueFull, sl.Type+"|"+sl.Value)
	}

	commonVals := []any{
		entry.CreatedAt,
		entry.UpdatedAt,
		entry.EntryId,
		entry.SpiffeId,
		entry.ParentId,
		entry.Admin,
		entry.Downstream,
		entry.X509SvidTtl,
		entry.EntryExpiry,
		entry.RevisionNumber,
		entry.StoreSvid,
		entry.Hint,
		entry.JwtSvidTtl,
		entry.DnsNames,
		entry.FederatesWith,
		selectorTypes,
		selectorValues,
		indexes,
		selectorTypeValueFull,
		entry.FederatesWith,
	}

	b.Entries = []gocql.BatchEntry{
		{
			Stmt: createEntryQuery,
			Args: append(commonVals, "", ""),
		},
	}

	for _, sl := range entry.Selectors {
		selVal := sl.Type + "|" + sl.Value

		b.Entries = append(b.Entries, gocql.BatchEntry{
			Stmt: createEntryQuery,
			Args: append(commonVals, selVal, ""),
		})
	}

	for _, ftd := range entry.FederatesWith {
		b.Entries = append(b.Entries, gocql.BatchEntry{
			Stmt: createEntryQuery,
			Args: append(commonVals, "", ftd),
		})
	}

	if err := b.ExecContext(ctx); err != nil {
		return nil, newWrappedCassandraError(err)
	}

	return entry, nil
}

// Copied verbatim from pkg/server/datastore/sqlstore/sqlstore.go:39
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

// copied verbatim from pkg/server/datastore/sqlstore/sqlstore.go:4451
// TODO(tjons): refactor this out into some helpers
func validateRegistrationEntry(entry *datastorev1.RegistrationEntry) error {
	if entry == nil {
		return newValidationError("invalid request: missing registered entry")
	}

	if len(entry.Selectors) == 0 {
		return newValidationError("invalid registration entry: missing selector list")
	}

	// In case of StoreSvid is set, all entries 'must' be the same type,
	// it is done to avoid users to mix selectors from different platforms in
	// entries with storable SVIDs
	if entry.StoreSvid {
		// Selectors must never be empty
		tpe := entry.Selectors[0].Type
		for _, t := range entry.Selectors {
			if tpe != t.Type {
				return newValidationError("invalid registration entry: selector types must be the same when store SVID is enabled")
			}
		}
	}

	if len(entry.EntryId) > 255 {
		return newValidationError("invalid registration entry: entry ID too long")
	}

	for _, e := range entry.EntryId {
		if !unicode.In(e, validEntryIDChars) {
			return newValidationError("invalid registration entry: entry ID contains invalid characters")
		}
	}

	if len(entry.SpiffeId) == 0 {
		return newValidationError("invalid registration entry: missing SPIFFE ID")
	}

	if entry.X509SvidTtl < 0 {
		return newValidationError("invalid registration entry: X509SvidTtl is not set")
	}

	if entry.JwtSvidTtl < 0 {
		return newValidationError("invalid registration entry: JwtSvidTtl is not set")
	}

	return nil
}

func (p *Plugin) CreateOrReturnRegistrationEntry(ctx context.Context, req *datastorev1.CreateOrReturnRegistrationEntryRequest) (*datastorev1.CreateOrReturnRegistrationEntryResponse, error) {
	if err := validateRegistrationEntry(req.Entry); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	resp, err := p.ListRegistrationEntries(ctx, &datastorev1.ListRegistrationEntriesRequest{
		ByParentId: req.Entry.ParentId,
		BySpiffeId: req.Entry.SpiffeId,
		BySelectors: &datastorev1.BySelectors{
			MatchBehavior: datastorev1.MatchBehavior_MATCH_BEHAVIOR_MATCH_EXACT,
			Selectors:     req.Entry.Selectors,
		},
	})
	if err != nil {
		return &datastorev1.CreateOrReturnRegistrationEntryResponse{
			Created: false,
		}, newWrappedCassandraError(err)
	}

	if len(resp.Entries) > 0 {
		return &datastorev1.CreateOrReturnRegistrationEntryResponse{
			Entry:   resp.Entries[0],
			Created: false,
		}, nil
	}

	createEntryResp, err := p.CreateRegistrationEntry(ctx, &datastorev1.CreateRegistrationEntryRequest{
		Entry: req.Entry,
	})
	if err != nil {
		return nil, err
	}
	newEntry := createEntryResp.GetEntry()

	if err := p.createRegistrationEntryEvent(ctx, &datastorev1.RegistrationEntryEvent{
		EntryId: newEntry.EntryId,
	}); err != nil {
		return nil, err
	}

	return &datastorev1.CreateOrReturnRegistrationEntryResponse{
		Entry:   newEntry,
		Created: true,
	}, nil
}

func (p *Plugin) DeleteRegistrationEntry(ctx context.Context, req *datastorev1.DeleteRegistrationEntryRequest) (*datastorev1.DeleteRegistrationEntryResponse, error) {
	entries, err := p.fetchRegistrationEntries(ctx, []string{req.EntryId})
	if err != nil {
		return nil, newWrappedCassandraError(err)
	}

	if entries[req.EntryId] == nil {
		return nil, status.Error(codes.NotFound, NotFoundErr.Error())
	}

	if err := p.deleteRegistrationEntry(ctx, entries[req.EntryId]); err != nil {
		return nil, newWrappedCassandraError(err)
	}

	if err := p.createRegistrationEntryEvent(ctx, &datastorev1.RegistrationEntryEvent{
		EntryId: req.EntryId,
	}); err != nil {
		return nil, err
	}

	return &datastorev1.DeleteRegistrationEntryResponse{
		Entry: entries[req.EntryId],
	}, nil
}

func (p *Plugin) deleteRegistrationEntry(ctx context.Context, re *datastorev1.RegistrationEntry) error {
	b := p.db.session.Batch(gocql.LoggedBatch).Consistency(p.db.cfg.WriteConsistency)

	const deleteEntryRowsQuery = `DELETE FROM registered_entries WHERE entry_id = ?`
	const deleteFederatedBundlesQuery = `DELETE FROM bundles WHERE trust_domain = ? AND federated_entry_id = ?`
	b.Entries = []gocql.BatchEntry{
		{
			Stmt:       deleteEntryRowsQuery,
			Args:       []any{re.EntryId},
			Idempotent: true,
		},
	}

	for _, ftd := range re.FederatesWith {
		b.Entries = append(b.Entries, gocql.BatchEntry{
			Stmt:       deleteFederatedBundlesQuery,
			Args:       []any{ftd, re.EntryId},
			Idempotent: true,
		})
	}

	if err := b.ExecContext(ctx); err != nil {
		return newWrappedCassandraError(err)
	}

	return nil
}

func (p *Plugin) FetchRegistrationEntry(ctx context.Context, req *datastorev1.FetchRegistrationEntryRequest) (*datastorev1.FetchRegistrationEntryResponse, error) {
	entries, err := p.fetchRegistrationEntries(ctx, []string{req.EntryId})
	if err != nil {
		return nil, err
	}

	return &datastorev1.FetchRegistrationEntryResponse{
		Entry: entries[req.EntryId],
	}, nil
}

func (p *Plugin) fetchRegistrationEntries(ctx context.Context, entryIDs []string) (map[string]*datastorev1.RegistrationEntry, error) {
	fetchRegistrationEntriesQuery := `
		SELECT
			created_at,
			updated_at,
			entry_id,
			spiffe_id,
			parent_id,
			ttl,
			admin,
			downstream,
			expiry,
			revision_number,
			store_svid,
			hint,
			jwt_svid_ttl,
			dns_names,
			federated_trust_domains,
			selector_type_value_full
		FROM registered_entries
	`

	args := []any{}
	cleanedEntryIDs := make([]string, 0, len(entryIDs))
	for _, id := range entryIDs {
		if len(id) > 0 {
			cleanedEntryIDs = append(cleanedEntryIDs, id)
		}
	}
	if len(cleanedEntryIDs) > 0 {
		args = append(args, cleanedEntryIDs)
		fetchRegistrationEntriesQuery += " WHERE entry_id IN ? ALLOW FILTERING"
	}
	// TODO(tjons): I don't think we need to ALLOW FILTERING here because we have an SAI on entry_id
	// but cassandra is rejecting the query during the statement preparation phase unless we include it.
	// Investigate further.

	query := p.db.session.Query(fetchRegistrationEntriesQuery, args...).Consistency(p.db.cfg.ReadConsistency)

	iter := query.IterContext(ctx)
	entryMap := make(map[string]*datastorev1.RegistrationEntry, iter.NumRows())
	scanner := iter.Scanner()

	// Since entries can have multiple selectors, we need to aggregate them

	for scanner.Next() {
		var (
			result    = new(datastorev1.RegistrationEntry)
			selectors = []string{}
			rnum      int64
		)

		err := scanner.Scan(
			&result.CreatedAt,
			&result.UpdatedAt,
			&result.EntryId,
			&result.SpiffeId,
			&result.ParentId,
			&result.X509SvidTtl,
			&result.Admin,
			&result.Downstream,
			&result.EntryExpiry,
			&rnum,
			&result.StoreSvid,
			&result.Hint,
			&result.JwtSvidTtl,
			&result.DnsNames,
			&result.FederatesWith,
			&selectors,
		)
		if err != nil {
			return nil, newWrappedCassandraError(err)
		}

		result.RevisionNumber = rnum
		result.Selectors = selectorStringsToSelectorObjs(selectors)
		entryMap[result.EntryId] = result
	}

	if err := scanner.Err(); err != nil {
		return nil, newWrappedCassandraError(err)
	}

	return entryMap, nil
}

func (p *Plugin) FetchRegistrationEntries(ctx context.Context, req *datastorev1.FetchRegistrationEntriesRequest) (*datastorev1.FetchRegistrationEntriesResponse, error) {
	resp, err := p.fetchRegistrationEntries(ctx, req.EntryIds)
	if err != nil {
		return nil, err
	}

	return &datastorev1.FetchRegistrationEntriesResponse{
		Entries: slices.Collect(maps.Values(resp)),
	}, nil
}

type queryTerm struct {
	field              string
	operator           string
	values             []any
	deepValues         [][]any
	requireDistinct    bool
	includeExtraColumn bool
}

func (p *Plugin) ListRegistrationEntries(ctx context.Context, req *datastorev1.ListRegistrationEntriesRequest) (*datastorev1.ListRegistrationEntriesResponse, error) {
	if req.Pagination != nil {
		if req.Pagination.PageSize == 0 {
			return nil, status.Error(codes.InvalidArgument, "cannot paginate with pagesize = 0")
		}

		if len(req.Pagination.PageToken) > 0 {
			pToken, err := base64.URLEncoding.Strict().DecodeString(req.Pagination.PageToken)
			if err != nil {
				return nil, status.Errorf(codes.InvalidArgument, "could not parse token '%s'", req.Pagination.PageToken)
			}
			req.Pagination.PageToken = string(pToken) // TODO(tjons): clean this up and avoid the mutation
		}
	}
	if req.BySelectors != nil && len(req.BySelectors.Selectors) == 0 {
		return nil, status.Error(codes.InvalidArgument, "cannot list by empty selector set")
	}

	collapseToPartitionRow := true
	onlyFiltersStaticCols := true
	terms := []queryTerm{}
	if len(req.ByParentId) > 0 {
		terms = append(terms, queryTerm{
			field:    "parent_id",
			operator: "=",
			values:   []any{req.ByParentId},
		})
	}

	if len(req.BySpiffeId) > 0 {
		terms = append(terms, queryTerm{
			field:    "spiffe_id",
			operator: "=",
			values:   []any{req.BySpiffeId},
		})
	}

	if req.FilterByDownstream {
		terms = append(terms, queryTerm{
			field:    "downstream",
			operator: "=",
			values:   []any{req.DownstreamValue},
		})
	}

	if len(req.ByHint) > 0 {
		terms = append(terms, queryTerm{
			field:    "hint",
			operator: "=",
			values:   []any{req.ByHint},
		})
	}

	if req.ByFederatesWith != nil || req.BySelectors != nil {
		indexes := generateSearchIndexesForRequest(req)
		terms = append(terms, indexes...)
		// TODO(tjons): this has to be temp

		for _, idx := range indexes {
			if idx.operator == "IN" {
				collapseToPartitionRow = false
			}
		}
	}

	addDistinctionColumn := false
	b := strings.Builder{}
	b.WriteString(`
		SELECT
			created_at,
			updated_at,
			entry_id,
			spiffe_id,
			parent_id,
			ttl,
			admin,
			downstream,
			expiry,
			revision_number,
			store_svid,
			hint,
			jwt_svid_ttl,
			dns_names,
			federated_trust_domains,
			selector_types,
			selector_values
		FROM registered_entries  
	`)
	if collapseToPartitionRow {
		// b.WriteString(" unrolled_selector_type_val = '' AND unrolled_ftd = '' ") // no filtering at all, get all entries but limit this to the empty row for paging
		// if len(terms) > 0 {
		// 	b.WriteString(" AND ")
		// }
		// needsDistinct = true
	}

	args := make([]any, 0, len(terms))
	if len(terms) > 0 {
		b.WriteString("WHERE ")

		for i, term := range terms {
			if i > 0 {
				b.WriteString(" AND ")
			}
			b.WriteString(term.field)
			b.WriteString(" ")
			b.WriteString(term.operator)

			if term.operator == "IN" {
				if !addDistinctionColumn {
					addDistinctionColumn = term.includeExtraColumn
					onlyFiltersStaticCols = false
				}

				if term.requireDistinct {
					onlyFiltersStaticCols = true
				}
				// TODO(tjons): the logic in here is actually kinda dangerous
				if len(term.deepValues) > 0 {
					b.WriteString(" (")
					b.WriteString(strings.TrimRight(strings.Repeat(" ?,", len(term.deepValues)), ","))
					b.WriteString(")")
					for _, dv := range term.deepValues {
						args = append(args, dv)
					}
					continue
				}

				b.WriteString(" (")
				b.WriteString(strings.TrimRight(strings.Repeat(" ?,", len(term.values)), ","))
				b.WriteString(")")
			} else {
				b.WriteString(" ?")
			}

			args = append(args, term.values...)
		}
	}

	b.WriteString(" ALLOW FILTERING")

	query := b.String()
	if !addDistinctionColumn {
		query = strings.Replace(query, "updated_at,", "", 1)
	}

	if onlyFiltersStaticCols {
		query = strings.Replace(query, "SELECT", "SELECT DISTINCT", 1)
	}

	cqlQuery := p.db.session.Query(query, args...).Consistency(p.db.cfg.ReadConsistency)

	if req.Pagination != nil {
		cqlQuery.PageSize(int(req.Pagination.PageSize))

		if len(req.Pagination.PageToken) > 0 {
			cqlQuery = cqlQuery.PageState([]byte(req.Pagination.PageToken))
		} else {
			cqlQuery = cqlQuery.PageState(nil)
		}
	} else {
		cqlQuery.PageSize(100_000_000) // effectively no limit
	}

	iter := cqlQuery.IterContext(ctx)
	entryMap := make(map[string]*datastorev1.RegistrationEntry, iter.NumRows())
	scanner := iter.Scanner()

	for scanner.Next() {
		var (
			result                        = new(datastorev1.RegistrationEntry)
			selectorTypes, selectorValues []string
			err                           error
		)

		if !addDistinctionColumn {
			err = scanner.Scan(
				&result.CreatedAt,
				&result.EntryId,
				&result.SpiffeId,
				&result.ParentId,
				&result.X509SvidTtl,
				&result.Admin,
				&result.Downstream,
				&result.EntryExpiry,
				&result.RevisionNumber,
				&result.StoreSvid,
				&result.Hint,
				&result.JwtSvidTtl,
				&result.DnsNames,
				&result.FederatesWith,
				&selectorTypes,
				&selectorValues,
			)
		} else {
			err = scanner.Scan(
				&result.CreatedAt,
				&result.UpdatedAt,
				&result.EntryId,
				&result.SpiffeId,
				&result.ParentId,
				&result.X509SvidTtl,
				&result.Admin,
				&result.Downstream,
				&result.EntryExpiry,
				&result.RevisionNumber,
				&result.StoreSvid,
				&result.Hint,
				&result.JwtSvidTtl,
				&result.DnsNames,
				&result.FederatesWith,
				&selectorTypes,
				&selectorValues,
			)
		}
		if err != nil {
			return nil, newWrappedCassandraError(err)
		}

		for i := range selectorTypes {
			selector := &datastorev1.Selector{
				Type:  selectorTypes[i],
				Value: selectorValues[i],
			}
			result.Selectors = append(result.Selectors, selector)
		}

		entryMap[result.EntryId] = result
	}

	if err := scanner.Err(); err != nil {
		return nil, newWrappedCassandraError(err)
	}
	pageState := iter.PageState()

	r := &datastorev1.ListRegistrationEntriesResponse{
		Entries: slices.Collect(maps.Values(entryMap)),
	}

	if req.Pagination != nil {
		r.Pagination = &datastorev1.Pagination{
			PageSize: req.Pagination.PageSize,
		}

		// go ahead and "peek"	if there is a next page...
		peeker := p.db.session.Query(query, args...).Consistency(p.db.cfg.ReadConsistency)

		peeker.PageState(pageState)
		peeker.PageSize(1)                  // I hate all this and i think it would be better if we just dropped the silly next pagination requirement for cassandra
		peekIter := peeker.IterContext(ctx) // at a minimum, we should feature flag this
		if peekIter.NumRows() > 0 {
			r.Pagination.PageToken = base64.URLEncoding.Strict().EncodeToString(pageState)
		}
		if err := peekIter.Close(); err != nil {
			return nil, newWrappedCassandraError(err)
		}
	}

	return r, nil
}

func (p *Plugin) PruneRegistrationEntries(ctx context.Context, req *datastorev1.PruneRegistrationEntriesRequest) (*datastorev1.PruneRegistrationEntriesResponse, error) {
	selectPruneQuery := `
		SELECT DISTINCT entry_id, spiffe_id, parent_id, federated_trust_domains FROM registered_entries WHERE expiry < ? AND expiry > 0 ALLOW FILTERING
		`
	query := p.db.session.Query(selectPruneQuery, req.ExpiresBefore).Consistency(p.db.cfg.ReadConsistency)
	iter := query.IterContext(ctx)

	type entryToPrune struct {
		entryID               string
		spiffeID              string
		parentID              string
		federatedTrustDomains []string
	}

	entries := make([]entryToPrune, 0, iter.NumRows())
	scanner := iter.Scanner()

	for scanner.Next() {
		var entry entryToPrune
		err := scanner.Scan(&entry.entryID, &entry.spiffeID, &entry.parentID, &entry.federatedTrustDomains)
		if err != nil {
			return nil, newWrappedCassandraError(err)
		}
		entries = append(entries, entry)
	}
	if err := iter.Close(); err != nil {
		return nil, newWrappedCassandraError(err)
	}

	deletePruneQueryBuilder := strings.Builder{}
	deletePruneQueryBuilder.WriteString(`DELETE FROM registered_entries WHERE entry_id IN (`)

	delIds := make([]any, len(entries))
	b := p.db.session.Batch(gocql.LoggedBatch).Consistency(p.db.cfg.WriteConsistency)

	for i := range entries {
		if i > 0 {
			deletePruneQueryBuilder.WriteString(",")
		}
		deletePruneQueryBuilder.WriteString("?")

		if len(entries[i].federatedTrustDomains) > 0 {
			deleteBundlesArgs := make([]any, 0)
			deleteBundlesQueryBuilder := strings.Builder{}
			deleteBundlesQueryBuilder.WriteString(`DELETE FROM bundles WHERE trust_domain IN (`)
			for _, td := range entries[i].federatedTrustDomains {
				deleteBundlesQueryBuilder.WriteString("?,")
				deleteBundlesArgs = append(deleteBundlesArgs, td)
			}
			deleteBundlesQueryBuilder.WriteString(")")
			deleteBundlesQueryBuilder.WriteString(" AND federated_entry_id = ?")
			deleteBundlesArgs = append(deleteBundlesArgs, entries[i].entryID)

			b.Query(deleteBundlesQueryBuilder.String(), deleteBundlesArgs...)
		}

		delIds[i] = entries[i].entryID
	}
	deletePruneQueryBuilder.WriteString(")")

	b.Query(deletePruneQueryBuilder.String(), delIds...)

	if err := b.ExecContext(ctx); err != nil {
		return nil, newWrappedCassandraError(err)
	}

	for _, entry := range entries {
		if err := p.createRegistrationEntryEvent(ctx, &datastorev1.RegistrationEntryEvent{
			EntryId: entry.entryID,
		}); err != nil {
			p.log.WithError(err).WithField(telemetry.RegistrationID, entry.entryID).Error("Failed to create registration entry event for pruned entry")
		}

		p.log.WithFields(logrus.Fields{
			telemetry.SPIFFEID:       entry.spiffeID,
			telemetry.ParentID:       entry.parentID,
			telemetry.RegistrationID: entry.entryID,
		}).Info("Pruned an expired registration")
	}

	return &datastorev1.PruneRegistrationEntriesResponse{}, nil
}

func (p *Plugin) UpdateRegistrationEntry(ctx context.Context, req *datastorev1.UpdateRegistrationEntryRequest) (*datastorev1.UpdateRegistrationEntryResponse, error) {
	if req.GetEntry() == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid request: missing registration entry")
	}

	re := req.GetEntry()
	mask := req.GetMask()

	if err := validateRegistrationEntryForUpdate(re, mask); err != nil {
		return nil, err
	}

	entryResp, err := p.FetchRegistrationEntry(ctx, &datastorev1.FetchRegistrationEntryRequest{
		EntryId: re.EntryId,
	})
	if err != nil {
		return nil, newWrappedCassandraError(err)
	}
	if entryResp.GetEntry() == nil {
		return nil, status.Error(codes.NotFound, NotFoundErr.Error())
	}
	entry := entryResp.GetEntry()

	b := p.db.session.Batch(gocql.LoggedBatch).Consistency(p.db.cfg.WriteConsistency)
	updateQuery := qb.NewUpdate().
		Table("registered_entries").
		Set("updated_at", qb.CqlFunction("toTimestamp(now())")).
		Where("entry_id", qb.Equals(re.EntryId))

	if mask == nil || mask.StoreSvid {
		entry.StoreSvid = re.StoreSvid
		updateQuery = updateQuery.Set("store_svid", re.StoreSvid)
	}

	selectors := make(map[string]*datastorev1.Selector, len(re.Selectors))
	selectorsToDelete := make(map[string]*datastorev1.Selector, len(entry.Selectors))
	if mask == nil || mask.Selectors {
		for _, s := range entry.Selectors {
			key := selectorToString(s)
			selectorsToDelete[key] = s
		}

		for _, s := range re.Selectors {
			key := selectorToString(s)
			selectors[key] = s
			delete(selectorsToDelete, key)
		}

		entry.Selectors = slices.Collect(maps.Values(selectors))
		stvFull := slices.Collect(maps.Keys(selectors))
		slices.Sort(stvFull)
		updateQuery = updateQuery.Set("selector_type_value_full", stvFull)

		for stvToDelete := range selectorsToDelete {
			deleteQuery := qb.NewDelete().
				From("registered_entries").
				Where("entry_id", qb.Equals(re.EntryId)).
				Where("unrolled_selector_type_val", qb.Equals(stvToDelete))

			q, _ := deleteQuery.Build()
			b.Query(q, deleteQuery.QueryValues()...)
		}

	}

	if entry.StoreSvid {
		typ := ""

		// Ensure that all selectors are of the same type
		for _, s := range selectors {
			switch {
			case typ == "":
				typ = s.Type
			case typ != s.Type:
				return nil, status.Error(codes.InvalidArgument, newValidationError("invalid registration entry: selector types must be the same when store SVID is enabled").Error())
			}
		}
	}

	if mask == nil || mask.DnsNames {
		entry.DnsNames = re.DnsNames
		updateQuery = updateQuery.Set("dns_names", re.DnsNames)
	}

	if mask == nil || mask.SpiffeId {
		entry.SpiffeId = re.SpiffeId
		updateQuery = updateQuery.Set("spiffe_id", re.SpiffeId)
	}

	if mask == nil || mask.ParentId {
		entry.ParentId = re.ParentId
		updateQuery = updateQuery.Set("parent_id", re.ParentId)
	}

	if mask == nil || mask.X509SvidTtl {
		entry.X509SvidTtl = re.X509SvidTtl
		updateQuery = updateQuery.Set("ttl", re.X509SvidTtl)
	}

	if mask == nil || mask.JwtSvidTtl {
		entry.JwtSvidTtl = re.JwtSvidTtl
		updateQuery = updateQuery.Set("jwt_svid_ttl", re.JwtSvidTtl)
	}

	if mask == nil || mask.Admin {
		entry.Admin = re.Admin
		updateQuery = updateQuery.Set("admin", re.Admin)
	}

	if mask == nil || mask.Downstream {
		entry.Downstream = re.Downstream
		updateQuery = updateQuery.Set("downstream", re.Downstream)
	}

	if mask == nil || mask.EntryExpiry {
		entry.EntryExpiry = re.EntryExpiry
		updateQuery = updateQuery.Set("expiry", re.EntryExpiry)
	}

	if mask == nil || mask.Hint {
		entry.Hint = re.Hint
		updateQuery = updateQuery.Set("hint", re.Hint)
	}

	if mask == nil || mask.FederatesWith {
		// TODO(tjons): probably smarter to set the read path to only read from static cols so that we do not have to worry about
		// potential inconsistencies
		updateQuery.Set("federated_trust_domains_full", re.FederatesWith)
		updateQuery.Set("federated_trust_domains", re.FederatesWith)

		trustDomainsToDelete := make(map[string]struct{}, len(entry.FederatesWith))
		for _, td := range entry.FederatesWith {
			trustDomainsToDelete[td] = struct{}{}
		}
		for _, td := range re.FederatesWith {
			delete(trustDomainsToDelete, td)
		}

		for tdToDelete := range trustDomainsToDelete {
			deleteFieldQuery := qb.NewDelete().
				From("registered_entries").
				Where("entry_id", qb.Equals(re.EntryId)).
				Where("unrolled_selector_type_val", qb.Equals("")).
				Where("unrolled_ftd", qb.Equals(tdToDelete))

			q, _ := deleteFieldQuery.Build()
			b.Query(q, deleteFieldQuery.QueryValues()...)

			deleteFtdLinkQuery := qb.NewDelete().
				From("bundles").
				Where("trust_domain", qb.Equals(tdToDelete)).
				Where("federated_entry_id", qb.Equals(re.EntryId))

			q, _ = deleteFtdLinkQuery.Build()
			b.Query(q, deleteFtdLinkQuery.QueryValues()...)
		}

		// make sure to do the write to the read object here, instead of anywhere earlier.
		entry.FederatesWith = re.FederatesWith
	}

	entry.RevisionNumber++

	updateQuery.Set("revision_number", entry.RevisionNumber)

	// Rebuild indexes
	updateQuery.Set("index_terms", buildIndexesForRegistrationEntry(entry))

	// It's easiest for us to write to the NULL rows for these unrolled columns
	// here and then handle updating them in a separate batch query.
	updateQuery.Where("unrolled_ftd", qb.Equals(""))
	updateQuery.Where("unrolled_selector_type_val", qb.Equals(""))

	q, _ := updateQuery.Build()
	b.Query(q, updateQuery.QueryValues()...)

	if err := b.ExecContext(ctx); err != nil {
		return nil, newWrappedCassandraError(err)
	}

	err = p.createRegistrationEntryEvent(ctx, &datastorev1.RegistrationEntryEvent{
		EntryId: re.EntryId,
	})
	if err != nil {
		return nil, newWrappedCassandraError(err)
	}

	return &datastorev1.UpdateRegistrationEntryResponse{
		Entry: entry,
	}, nil
}

func validateRegistrationEntryForUpdate(entry *datastorev1.RegistrationEntry, mask *datastorev1.RegistrationEntryMask) error {
	if entry == nil {
		return newValidationError("invalid request: missing registered entry")
	}

	if (mask == nil || mask.Selectors) && len(entry.Selectors) == 0 {
		return newValidationError("invalid registration entry: missing selector list")
	}

	if (mask == nil || mask.SpiffeId) &&
		entry.SpiffeId == "" {
		return newValidationError("invalid registration entry: missing SPIFFE ID")
	}

	if (mask == nil || mask.X509SvidTtl) &&
		(entry.X509SvidTtl < 0) {
		return newValidationError("invalid registration entry: X509SvidTtl is not set")
	}

	if (mask == nil || mask.JwtSvidTtl) &&
		(entry.JwtSvidTtl < 0) {
		return newValidationError("invalid registration entry: JwtSvidTtl is not set")
	}

	return nil
}
