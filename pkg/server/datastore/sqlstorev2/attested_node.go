package sqlstorev2

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/protoutil"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/pkg/server/datastore/sqlcommon"
	"github.com/spiffe/spire/proto/spire/common"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gorm.io/gorm"
)

const defaultPruneAttestedNodesBatchSize = 1000

// attestedNodeColumns are the columns a listed node is built from, in the
// order scanAttestedNode expects.
var attestedNodeColumns = []string{"attested_node_entries.id", "attested_node_entries.spiffe_id", "data_type", "serial_number", "expires_at", "new_serial_number", "new_expires_at", "can_reattest", "agent_version"}

func (ds *Plugin) CreateAttestedNode(ctx context.Context, node *common.AttestedNode) (attestedNode *common.AttestedNode, err error) {
	if node == nil {
		return nil, sqlcommon.NewSQLError("invalid request: missing attested node")
	}

	if err = ds.withWriteTx(ctx, func(tx *gorm.DB) (err error) {
		attestedNode, err = createAttestedNode(tx, node)
		if err != nil {
			return err
		}
		return createAttestedNodeEvent(tx, &datastore.AttestedNodeEvent{SpiffeID: node.SpiffeId})
	}); err != nil {
		return nil, err
	}
	return attestedNode, nil
}

// FetchAttestedNode returns nil if the node does not exist.
func (ds *Plugin) FetchAttestedNode(ctx context.Context, spiffeID string) (attestedNode *common.AttestedNode, err error) {
	if err = ds.withReadTx(ctx, func(tx *gorm.DB) (err error) {
		attestedNode, err = fetchAttestedNode(tx, spiffeID)
		return err
	}); err != nil {
		return nil, err
	}
	return attestedNode, nil
}

func (ds *Plugin) CountAttestedNodes(ctx context.Context, req *datastore.CountAttestedNodesRequest) (count int32, err error) {
	if err = ds.withReadDB(ctx, datastore.RequireCurrent, func(tx *gorm.DB) (err error) {
		count, err = countAttestedNodes(tx, ds.DatabaseType(), req)
		return err
	}); err != nil {
		return 0, err
	}
	return count, nil
}

func (ds *Plugin) ListAttestedNodes(ctx context.Context, req *datastore.ListAttestedNodesRequest) (resp *datastore.ListAttestedNodesResponse, err error) {
	if err = ds.withReadDB(ctx, datastore.RequireCurrent, func(tx *gorm.DB) (err error) {
		resp, err = listAttestedNodes(tx, ds.DatabaseType(), req)
		return err
	}); err != nil {
		return nil, err
	}
	return resp, nil
}

// UpdateAttestedNode updates the fields of the given node selected by mask. A
// nil mask updates every field.
func (ds *Plugin) UpdateAttestedNode(ctx context.Context, n *common.AttestedNode, mask *common.AttestedNodeMask) (node *common.AttestedNode, err error) {
	if n == nil {
		return nil, sqlcommon.NewSQLError("invalid request: missing attested node")
	}
	if err = ds.withReadModifyWriteTx(ctx, func(tx *gorm.DB) (err error) {
		node, err = updateAttestedNode(tx, n, mask)
		if err != nil {
			return err
		}
		return createAttestedNodeEvent(tx, &datastore.AttestedNodeEvent{SpiffeID: n.SpiffeId})
	}); err != nil {
		return nil, err
	}
	return node, nil
}

// DeleteAttestedNode deletes the given attested node and its selectors. Join
// token nodes are refused with Unimplemented until their alias entries can be
// deleted too.
func (ds *Plugin) DeleteAttestedNode(ctx context.Context, spiffeID string) (attestedNode *common.AttestedNode, err error) {
	if err = ds.withWriteTx(ctx, func(tx *gorm.DB) (err error) {
		attestedNode, err = deleteAttestedNodeAndSelectors(tx, spiffeID)
		if err != nil {
			return err
		}
		return createAttestedNodeEvent(tx, &datastore.AttestedNodeEvent{SpiffeID: spiffeID})
	}); err != nil {
		return nil, err
	}
	return attestedNode, nil
}

// PruneAttestedExpiredNodes deletes up to batchSize (default if non-positive)
// nodes that expired before expiredBefore, keeping banned nodes and, unless
// includeNonReattestable is set, non-reattestable ones. Join token nodes are
// skipped, as DeleteAttestedNode refuses them.
func (ds *Plugin) PruneAttestedExpiredNodes(ctx context.Context, expiredBefore time.Time, includeNonReattestable bool, batchSize int) error {
	return ds.withWriteTx(ctx, func(tx *gorm.DB) error {
		return pruneAttestedExpiredNodes(tx, expiredBefore, includeNonReattestable, batchSize, ds.log)
	})
}

func (ds *Plugin) ListAttestedNodeEvents(ctx context.Context, req *datastore.ListAttestedNodeEventsRequest) (resp *datastore.ListAttestedNodeEventsResponse, err error) {
	if req.GreaterThanEventID != 0 && req.LessThanEventID != 0 {
		return nil, sqlcommon.NewSQLError("can't set both greater and less than event id")
	}
	if err = ds.withReadDB(ctx, req.DataConsistency, func(tx *gorm.DB) (err error) {
		resp, err = listAttestedNodeEvents(tx, req)
		return err
	}); err != nil {
		return nil, err
	}
	return resp, nil
}

func (ds *Plugin) PruneAttestedNodeEvents(ctx context.Context, olderThan time.Duration) error {
	return ds.withWriteTx(ctx, func(tx *gorm.DB) error {
		return pruneAttestedNodeEvents(tx, olderThan)
	})
}

func (ds *Plugin) CreateAttestedNodeEventForTesting(ctx context.Context, event *datastore.AttestedNodeEvent) error {
	return ds.withWriteTx(ctx, func(tx *gorm.DB) error {
		return createAttestedNodeEvent(tx, event)
	})
}

func (ds *Plugin) DeleteAttestedNodeEventForTesting(ctx context.Context, eventID uint) error {
	return ds.withWriteTx(ctx, func(tx *gorm.DB) error {
		return deleteAttestedNodeEvent(tx, eventID)
	})
}

func (ds *Plugin) FetchAttestedNodeEvent(ctx context.Context, eventID uint) (event *datastore.AttestedNodeEvent, err error) {
	if err = ds.withReadTx(ctx, func(tx *gorm.DB) (err error) {
		event, err = fetchAttestedNodeEvent(tx, eventID)
		return err
	}); err != nil {
		return nil, err
	}
	return event, nil
}

func (ds *Plugin) SetNodeSelectors(ctx context.Context, spiffeID string, selectors []*common.Selector) error {
	return ds.withWriteTx(ctx, func(tx *gorm.DB) error {
		if err := setNodeSelectors(tx, spiffeID, selectors); err != nil {
			return err
		}
		return createAttestedNodeEvent(tx, &datastore.AttestedNodeEvent{SpiffeID: spiffeID})
	})
}

func (ds *Plugin) GetNodeSelectors(ctx context.Context, spiffeID string, dataConsistency datastore.DataConsistency) (selectors []*common.Selector, err error) {
	if err = ds.withReadDB(ctx, dataConsistency, func(tx *gorm.DB) (err error) {
		// The statement text never varies, so preparing it once per connection
		// saves MySQL a prepare and close round-trip per call.
		rows, err := tx.Session(&gorm.Session{PrepareStmt: true}).Model(&NodeSelector{}).Select("type", "value").Where("spiffe_id = ?", spiffeID).Order("id").Rows()
		if err != nil {
			return sqlcommon.NewWrappedSQLError(err)
		}
		defer rows.Close()
		for rows.Next() {
			var selectorType, value sql.NullString
			if err := rows.Scan(&selectorType, &value); err != nil {
				return sqlcommon.NewWrappedSQLError(err)
			}
			selectors = append(selectors, &common.Selector{Type: selectorType.String, Value: value.String})
		}
		return sqlcommon.NewWrappedSQLError(rows.Err())
	}); err != nil {
		return nil, err
	}
	return selectors, nil
}

// ListNodeSelectors lists the selectors of every node, grouped by SPIFFE ID.
// When ValidAt is set, only nodes that are unexpired at that time are listed.
func (ds *Plugin) ListNodeSelectors(ctx context.Context, req *datastore.ListNodeSelectorsRequest) (resp *datastore.ListNodeSelectorsResponse, err error) {
	if err = ds.withReadDB(ctx, req.DataConsistency, func(tx *gorm.DB) error {
		query := tx.Model(&NodeSelector{}).Select("node_resolver_map_entries.spiffe_id, node_resolver_map_entries.type, node_resolver_map_entries.value")
		if !req.ValidAt.IsZero() {
			query = query.Joins("INNER JOIN attested_node_entries ON attested_node_entries.spiffe_id = node_resolver_map_entries.spiffe_id").
				Where("attested_node_entries.expires_at > ?", req.ValidAt)
		}

		resp = &datastore.ListNodeSelectorsResponse{Selectors: make(map[string][]*common.Selector)}
		rows, err := query.Order("node_resolver_map_entries.spiffe_id").Rows()
		if err != nil {
			return sqlcommon.NewWrappedSQLError(err)
		}
		defer rows.Close()
		for rows.Next() {
			var id string
			var selectorType, value sql.NullString
			if err := rows.Scan(&id, &selectorType, &value); err != nil {
				return sqlcommon.NewWrappedSQLError(err)
			}
			resp.Selectors[id] = append(resp.Selectors[id], &common.Selector{Type: selectorType.String, Value: value.String})
		}
		return sqlcommon.NewWrappedSQLError(rows.Err())
	}); err != nil {
		return nil, err
	}
	return resp, nil
}

func createAttestedNode(tx *gorm.DB, node *common.AttestedNode) (*common.AttestedNode, error) {
	model := AttestedNode{
		SpiffeID:        node.SpiffeId,
		DataType:        node.AttestationDataType,
		SerialNumber:    node.CertSerialNumber,
		ExpiresAt:       time.Unix(node.CertNotAfter, 0),
		NewSerialNumber: node.NewCertSerialNumber,
		NewExpiresAt:    nullableUnixTimeToDBTime(node.NewCertNotAfter),
		CanReattest:     node.CanReattest,
		AgentVersion:    node.AgentVersion,
	}
	if err := tx.Create(&model).Error; err != nil {
		return nil, sqlcommon.NewWrappedSQLError(err)
	}
	return modelToAttestedNode(model), nil
}

func fetchAttestedNode(tx *gorm.DB, spiffeID string) (*common.AttestedNode, error) {
	var model AttestedNode
	err := tx.Where("spiffe_id = ?", spiffeID).Take(&model).Error
	switch {
	case errors.Is(err, gorm.ErrRecordNotFound):
		return nil, nil
	case err != nil:
		return nil, sqlcommon.NewWrappedSQLError(err)
	}
	return modelToAttestedNode(model), nil
}

// nodeFilter holds the node filters shared by list and count requests.
type nodeFilter struct {
	byExpiresBefore   time.Time
	validAt           time.Time
	byAttestationType string
	byBanned          *bool
	byCanReattest     *bool
	bySpiffeIDs       []string
	bySelectorMatch   *datastore.BySelectors
}

func filterNodes(query *gorm.DB, dbType string, f nodeFilter) *gorm.DB {
	if !f.byExpiresBefore.IsZero() {
		query = query.Where("attested_node_entries.expires_at < ?", f.byExpiresBefore)
	}
	if !f.validAt.IsZero() {
		query = query.Where("attested_node_entries.expires_at >= ?", f.validAt)
	}
	if f.byAttestationType != "" {
		query = query.Where("attested_node_entries.data_type = ?", f.byAttestationType)
	}
	if f.byBanned != nil {
		if *f.byBanned {
			query = query.Where("attested_node_entries.serial_number = ''")
		} else {
			query = query.Where("attested_node_entries.serial_number <> ''")
		}
	}
	if f.byCanReattest != nil {
		query = query.Where("attested_node_entries.can_reattest = ?", *f.byCanReattest)
	}
	if len(f.bySpiffeIDs) > 0 {
		query = query.Where("attested_node_entries.spiffe_id IN ?", f.bySpiffeIDs)
	}
	if f.bySelectorMatch != nil {
		query = filterNodesBySelectors(query, dbType, f.bySelectorMatch)
	}
	return query
}

// filterNodesBySelectors restricts query to nodes whose selectors match by:
// MatchAny shares one with the set, Superset has all of it, Subset has only
// selectors from it (at least one), and Exact is both Superset and Subset.
func filterNodesBySelectors(query *gorm.DB, dbType string, by *datastore.BySelectors) *gorm.DB {
	selectors := uniqueSelectors(by.Selectors)
	inSet, args := selectorSetCondition(selectors, false)
	// The check for selectors outside the set compares case-sensitively, which
	// MySQL's default collations would not.
	inSetExact, _ := selectorSetCondition(selectors, sqlcommon.IsMySQLDbType(dbType))

	// Each call builds a new statement; gorm handles share state when chained.
	selectorRows := func(cond string) *gorm.DB {
		return query.Session(&gorm.Session{NewDB: true}).Model(&NodeSelector{}).Select("spiffe_id").Where(cond, args...)
	}
	matching := selectorRows(inSet)
	hasAll := selectorRows(inSet).Group("spiffe_id").Having("COUNT(*) = ?", len(selectors))
	if sqlcommon.IsMySQLDbType(dbType) {
		// MySQL collations ignore case, so one row can match two requested
		// selectors; each one is checked on its own instead.
		matchedEach := make([]string, len(selectors))
		for i := range selectors {
			matchedEach[i] = "MAX(CASE WHEN type = ? AND value = ? THEN 1 ELSE 0 END)"
		}
		hasAll = selectorRows(inSet).Group("spiffe_id").
			Having(strings.Join(matchedEach, " + ")+" = ?", append(slices.Clone(args), len(selectors))...)
	}
	// NOT EXISTS rather than NOT IN: PostgreSQL rescans a NOT IN subquery per
	// row once its result outgrows work_mem.
	outside := query.Session(&gorm.Session{NewDB: true}).Table("node_resolver_map_entries AS o").Select("1").
		Where("o.spiffe_id = attested_node_entries.spiffe_id").Where("NOT ("+inSetExact+")", args...)

	// Joining the matching set, rather than IN (subquery), lets PostgreSQL
	// build it once with a hash join instead of probing the selector index
	// once per node. Subset is the exception: there IN plans better.
	join := func(q, sub *gorm.DB) *gorm.DB {
		return q.Joins("JOIN (?) AS m ON m.spiffe_id = attested_node_entries.spiffe_id", sub)
	}

	switch by.Match {
	case datastore.MatchAny:
		return join(query, matching.Distinct())
	case datastore.Superset:
		return join(query, hasAll)
	case datastore.Subset:
		return query.Where("attested_node_entries.spiffe_id IN (?)", matching).Where("NOT EXISTS (?)", outside)
	default: // datastore.Exact; validateSelectorMatch rejects anything else.
		return join(query, hasAll).Where("NOT EXISTS (?)", outside)
	}
}

func validateSelectorMatch(by *datastore.BySelectors) error {
	if by == nil {
		return nil
	}
	if len(by.Selectors) == 0 {
		return status.Error(codes.InvalidArgument, "cannot list by empty selectors set")
	}
	switch by.Match {
	case datastore.MatchAny, datastore.Superset, datastore.Subset, datastore.Exact:
		return nil
	default:
		return status.Errorf(codes.InvalidArgument, "unhandled match behavior %d", by.Match)
	}
}

// selectorSetCondition returns a condition, and its arguments, that holds for
// node selector rows in the given set, comparing as binary strings if binary.
func selectorSetCondition(selectors []*common.Selector, binary bool) (string, []any) {
	cond := "(type = ? AND value = ?)"
	if binary {
		cond = "(CAST(type AS BINARY) = CAST(? AS BINARY) AND CAST(value AS BINARY) = CAST(? AS BINARY))"
	}
	conditions := make([]string, 0, len(selectors))
	args := make([]any, 0, 2*len(selectors))
	for _, s := range selectors {
		conditions = append(conditions, cond)
		args = append(args, s.Type, s.Value)
	}
	return strings.Join(conditions, " OR "), args
}

// uniqueSelectors returns selectors without duplicates, so a count of matching
// rows per node can be compared against the set size.
func uniqueSelectors(selectors []*common.Selector) []*common.Selector {
	type key struct{ t, v string }
	seen := make(map[key]struct{}, len(selectors))
	out := make([]*common.Selector, 0, len(selectors))
	for _, s := range selectors {
		k := key{s.Type, s.Value}
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, s)
	}
	return out
}

func countAttestedNodes(tx *gorm.DB, dbType string, req *datastore.CountAttestedNodesRequest) (int32, error) {
	if err := validateSelectorMatch(req.BySelectorMatch); err != nil {
		return 0, err
	}

	query := filterNodes(tx.Model(&AttestedNode{}), dbType, nodeFilter{
		byExpiresBefore:   req.ByExpiresBefore,
		byAttestationType: req.ByAttestationType,
		byBanned:          req.ByBanned,
		byCanReattest:     req.ByCanReattest,
		bySelectorMatch:   req.BySelectorMatch,
	})

	var count int64
	if err := query.Count(&count).Error; err != nil {
		return 0, sqlcommon.NewWrappedSQLError(err)
	}
	return util.CheckedCast[int32](count)
}

func listAttestedNodes(tx *gorm.DB, dbType string, req *datastore.ListAttestedNodesRequest) (*datastore.ListAttestedNodesResponse, error) {
	if req.Pagination != nil && req.Pagination.PageSize == 0 {
		return nil, status.Error(codes.InvalidArgument, "cannot paginate with pagesize = 0")
	}
	if err := validateSelectorMatch(req.BySelectorMatch); err != nil {
		return nil, err
	}

	query := filterNodes(tx.Model(&AttestedNode{}), dbType, nodeFilter{
		byExpiresBefore:   req.ByExpiresBefore,
		validAt:           req.ValidAt,
		byAttestationType: req.ByAttestationType,
		byBanned:          req.ByBanned,
		byCanReattest:     req.ByCanReattest,
		bySpiffeIDs:       req.BySpiffeIDs,
		bySelectorMatch:   req.BySelectorMatch,
	}).Select(attestedNodeColumns).Order("attested_node_entries.id")

	if p := req.Pagination; p != nil {
		query = query.Limit(int(p.PageSize))
		if p.Token != "" {
			id, err := parsePaginationToken(p.Token, dbType)
			if err != nil {
				return nil, err
			}
			query = query.Where("attested_node_entries.id > ?", id)
		}
	}

	var (
		nodes  []*common.AttestedNode
		lastID uint
	)
	if req.FetchSelectors {
		// Joining against the limited node query as a derived table keeps the
		// page size counting nodes rather than selector rows.
		rows, err := tx.Table("(?) AS n", query).
			Select("n.id, n.spiffe_id, n.data_type, n.serial_number, n.expires_at, n.new_serial_number, n.new_expires_at, n.can_reattest, n.agent_version, s.type, s.value").
			Joins("LEFT JOIN node_resolver_map_entries s ON s.spiffe_id = n.spiffe_id").
			Order("n.id, s.id").
			Rows()
		if err != nil {
			return nil, sqlcommon.NewWrappedSQLError(err)
		}
		defer rows.Close()
		var node *common.AttestedNode
		for rows.Next() {
			var sType, sVal sql.NullString
			m, err := scanAttestedNode(rows, &sType, &sVal)
			if err != nil {
				return nil, err
			}
			if node == nil || m.ID != lastID {
				lastID = m.ID
				node = modelToAttestedNode(m)
				nodes = append(nodes, node)
			}
			if sType.Valid {
				node.Selectors = append(node.Selectors, &common.Selector{Type: sType.String, Value: sVal.String})
			}
		}
		if err := rows.Err(); err != nil {
			return nil, sqlcommon.NewWrappedSQLError(err)
		}
	} else {
		rows, err := query.Rows()
		if err != nil {
			return nil, sqlcommon.NewWrappedSQLError(err)
		}
		defer rows.Close()
		for rows.Next() {
			m, err := scanAttestedNode(rows)
			if err != nil {
				return nil, err
			}
			nodes = append(nodes, modelToAttestedNode(m))
			lastID = m.ID
		}
		if err := rows.Err(); err != nil {
			return nil, sqlcommon.NewWrappedSQLError(err)
		}
	}

	resp := &datastore.ListAttestedNodesResponse{Nodes: nodes}
	if resp.Nodes == nil {
		resp.Nodes = []*common.AttestedNode{}
	}
	if p := req.Pagination; p != nil {
		resp.Pagination = &datastore.Pagination{PageSize: p.PageSize}
		if len(nodes) > 0 {
			resp.Pagination.Token = strconv.FormatUint(uint64(lastID), 10)
		}
	}
	return resp, nil
}

// scanAttestedNode scans a row whose leading columns are attestedNodeColumns
// into a model, and any further columns into extra. Columns other than id and
// spiffe_id may be NULL.
func scanAttestedNode(rows *sql.Rows, extra ...any) (AttestedNode, error) {
	var (
		m                                         AttestedNode
		dataType, serial, newSerial, agentVersion sql.NullString
		expiresAt, newExpiresAt                   sql.NullTime
		canReattest                               sql.NullBool
	)
	dest := append([]any{&m.ID, &m.SpiffeID, &dataType, &serial, &expiresAt, &newSerial, &newExpiresAt, &canReattest, &agentVersion}, extra...)
	if err := rows.Scan(dest...); err != nil {
		return AttestedNode{}, sqlcommon.NewWrappedSQLError(err)
	}
	m.DataType = dataType.String
	m.SerialNumber = serial.String
	m.ExpiresAt = expiresAt.Time
	m.NewSerialNumber = newSerial.String
	if newExpiresAt.Valid {
		m.NewExpiresAt = &newExpiresAt.Time
	}
	m.CanReattest = canReattest.Bool
	m.AgentVersion = agentVersion.String
	return m, nil
}

func updateAttestedNode(tx *gorm.DB, n *common.AttestedNode, mask *common.AttestedNodeMask) (*common.AttestedNode, error) {
	var model AttestedNode
	if err := tx.Where("spiffe_id = ?", n.SpiffeId).Take(&model).Error; err != nil {
		return nil, sqlcommon.NewWrappedSQLError(err)
	}

	if mask == nil {
		mask = protoutil.AllTrueCommonAgentMask
	}

	updates := make(map[string]any)
	if mask.CertNotAfter {
		updates["expires_at"] = time.Unix(n.CertNotAfter, 0)
	}
	if mask.CertSerialNumber {
		updates["serial_number"] = n.CertSerialNumber
	}
	if mask.NewCertNotAfter {
		updates["new_expires_at"] = nullableUnixTimeToDBTime(n.NewCertNotAfter)
	}
	if mask.NewCertSerialNumber {
		updates["new_serial_number"] = n.NewCertSerialNumber
	}
	if mask.CanReattest {
		updates["can_reattest"] = n.CanReattest
	}
	if mask.AgentVersion {
		updates["agent_version"] = n.AgentVersion
	}
	if err := tx.Model(&model).Updates(updates).Error; err != nil {
		return nil, sqlcommon.NewWrappedSQLError(err)
	}

	return modelToAttestedNode(model), nil
}

func deleteAttestedNodeAndSelectors(tx *gorm.DB, spiffeID string) (*common.AttestedNode, error) {
	var model AttestedNode
	if err := tx.Where("spiffe_id = ?", spiffeID).Take(&model).Error; err != nil {
		return nil, sqlcommon.NewWrappedSQLError(err)
	}
	// TODO: delete the join token alias registration entries once registration
	// entries are implemented; until then, refuse rather than leave them.
	if model.DataType == "join_token" {
		return nil, status.Error(codes.Unimplemented, "datastore-sql: deleting join token attested nodes is not implemented")
	}
	if err := tx.Where("spiffe_id = ?", spiffeID).Delete(&NodeSelector{}).Error; err != nil {
		return nil, sqlcommon.NewWrappedSQLError(err)
	}
	if err := tx.Delete(&model).Error; err != nil {
		return nil, sqlcommon.NewWrappedSQLError(err)
	}
	return modelToAttestedNode(model), nil
}

func pruneAttestedExpiredNodes(tx *gorm.DB, expiredBefore time.Time, includeNonReattestable bool, batchSize int, log logrus.FieldLogger) error {
	if batchSize <= 0 {
		batchSize = defaultPruneAttestedNodesBatchSize
	}

	expiredNodes := func() *gorm.DB {
		query := tx.Model(&AttestedNode{}).Where("expires_at < ?", expiredBefore).Where("serial_number <> ''")
		if !includeNonReattestable {
			query = query.Where("can_reattest = ?", true)
		}
		return query
	}

	// TODO: prune join token attested nodes once their deletion is implemented;
	// skipping them keeps one from failing every batch.
	var skipped int64
	if err := expiredNodes().Where("data_type = ?", "join_token").Count(&skipped).Error; err != nil {
		return sqlcommon.NewWrappedSQLError(err)
	}
	if skipped > 0 {
		log.WithField("count", skipped).Warn("Skipped pruning expired join token agents: not implemented")
	}

	var expired []AttestedNode
	if err := expiredNodes().Where("(data_type IS NULL OR data_type <> ?)", "join_token").Limit(batchSize).Find(&expired).Error; err != nil {
		return sqlcommon.NewWrappedSQLError(err)
	}

	for _, node := range expired {
		if _, err := deleteAttestedNodeAndSelectors(tx, node.SpiffeID); err != nil {
			return err
		}
		if err := createAttestedNodeEvent(tx, &datastore.AttestedNodeEvent{SpiffeID: node.SpiffeID}); err != nil {
			return err
		}
	}
	log.WithField("count", len(expired)).Info("Pruned expired agents")
	return nil
}

func setNodeSelectors(tx *gorm.DB, spiffeID string, selectors []*common.Selector) error {
	// Deleting by spiffe_id takes gap locks on MySQL that deadlock concurrent
	// calls, so delete the existing rows by primary key instead.
	var ids []int64
	if err := tx.Model(&NodeSelector{}).Where("spiffe_id = ?", spiffeID).Pluck("id", &ids).Error; err != nil {
		return sqlcommon.NewWrappedSQLError(err)
	}
	if len(ids) > 0 {
		if err := tx.Where("id IN ?", ids).Delete(&NodeSelector{}).Error; err != nil {
			return sqlcommon.NewWrappedSQLError(err)
		}
	}

	for _, selector := range selectors {
		if err := tx.Create(&NodeSelector{SpiffeID: spiffeID, Type: selector.Type, Value: selector.Value}).Error; err != nil {
			return sqlcommon.NewWrappedSQLError(err)
		}
	}
	return nil
}

func createAttestedNodeEvent(tx *gorm.DB, event *datastore.AttestedNodeEvent) error {
	model := AttestedNodeEvent{ID: event.EventID, SpiffeID: event.SpiffeID}
	if err := tx.Create(&model).Error; err != nil {
		return sqlcommon.NewWrappedSQLError(err)
	}
	return nil
}

func listAttestedNodeEvents(tx *gorm.DB, req *datastore.ListAttestedNodeEventsRequest) (*datastore.ListAttestedNodeEventsResponse, error) {
	query := tx.Order("id asc")
	if req.GreaterThanEventID != 0 {
		query = query.Where("id > ?", req.GreaterThanEventID)
	}
	if req.LessThanEventID != 0 {
		query = query.Where("id < ?", req.LessThanEventID)
	}

	var events []AttestedNodeEvent
	if err := query.Find(&events).Error; err != nil {
		return nil, sqlcommon.NewWrappedSQLError(err)
	}

	resp := &datastore.ListAttestedNodeEventsResponse{
		Events: make([]datastore.AttestedNodeEvent, len(events)),
	}
	for i, event := range events {
		resp.Events[i] = datastore.AttestedNodeEvent{EventID: event.ID, SpiffeID: event.SpiffeID}
	}
	return resp, nil
}

func pruneAttestedNodeEvents(tx *gorm.DB, olderThan time.Duration) error {
	if err := tx.Where("created_at < ?", time.Now().Add(-olderThan)).Delete(&AttestedNodeEvent{}).Error; err != nil {
		return sqlcommon.NewWrappedSQLError(err)
	}
	return nil
}

func fetchAttestedNodeEvent(tx *gorm.DB, eventID uint) (*datastore.AttestedNodeEvent, error) {
	var event AttestedNodeEvent
	if err := tx.Where("id = ?", eventID).Take(&event).Error; err != nil {
		return nil, sqlcommon.NewWrappedSQLError(err)
	}
	return &datastore.AttestedNodeEvent{EventID: event.ID, SpiffeID: event.SpiffeID}, nil
}

func deleteAttestedNodeEvent(tx *gorm.DB, eventID uint) error {
	if err := tx.Delete(&AttestedNodeEvent{ID: eventID}).Error; err != nil {
		return sqlcommon.NewWrappedSQLError(err)
	}
	return nil
}

func modelToAttestedNode(model AttestedNode) *common.AttestedNode {
	return &common.AttestedNode{
		SpiffeId:            model.SpiffeID,
		AttestationDataType: model.DataType,
		CertSerialNumber:    model.SerialNumber,
		CertNotAfter:        nullableDBTimeToUnixTime(&model.ExpiresAt),
		NewCertSerialNumber: model.NewSerialNumber,
		NewCertNotAfter:     nullableDBTimeToUnixTime(model.NewExpiresAt),
		CanReattest:         model.CanReattest,
		AgentVersion:        model.AgentVersion,
	}
}

func nullableUnixTimeToDBTime(unixTime int64) *time.Time {
	if unixTime == 0 {
		return nil
	}
	t := time.Unix(unixTime, 0)
	return &t
}

func nullableDBTimeToUnixTime(t *time.Time) int64 {
	if t == nil || t.IsZero() {
		return 0
	}
	return t.Unix()
}
