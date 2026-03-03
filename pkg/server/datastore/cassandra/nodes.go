package cassandra

import (
	"context"
	"errors"
	"maps"
	"slices"
	"time"

	gocql "github.com/apache/cassandra-gocql-driver/v2"
	datastorev1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/datastore/v1alpha1"
	"github.com/spiffe/spire/pkg/server/datastore/cassandra/qb"
	"github.com/spiffe/spire/pkg/server/datastore/cassandra/qb/pages"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (p *Plugin) CountAttestedNodes(ctx context.Context, req *datastorev1.CountAttestedNodesRequest) (*datastorev1.CountAttestedNodesResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}

	if req.BySelectors != nil && len(req.BySelectors.Selectors) == 0 {
		return nil, status.Error(codes.InvalidArgument, "cannot count by empty selectors set")
	}

	q := qb.NewSelect().
		Distinct().
		Column("spiffe_id").
		Column("COUNT(*)").
		From("attested_node_entries").
		AllowFiltering()

	if req.ByBanned {
		if req.BannedValue {
			// The original SQL implementation marks nodes as "banned" by setting
			// their serial number to an empty string. However, since Cassandra
			// does not support filtering with "!=" operator, we add a dedicated
			// "banned" boolean column to simplify queries.
			q.Where("banned", qb.Equals(true))
		} else {
			q.Where("banned", qb.Equals(false))
		}
	}
	if req.ByAttestationType != "" {
		q.Where("attestation_data_type", qb.Equals(req.ByAttestationType))
	}
	if req.ByExpiresBefore > 0 {
		q.Where("cert_not_after", qb.LessThan(req.ByExpiresBefore))
	}
	if req.ByCanReattest {
		q.Where("can_reattest", qb.Equals(req.ByCanReattest))
	}
	if req.BySelectors != nil {
		_ = generateSelectorFilters(req.BySelectors, q) // we don't care about the distinguishing column here
	}

	var (
		count          int32
		spiffeIDunused string
	)
	if err := p.db.ReadQuery(q).ScanContext(ctx, &spiffeIDunused, &count); err != nil {
		return nil, newWrappedCassandraError(err)
	}

	return &datastorev1.CountAttestedNodesResponse{
		Count: count,
	}, nil
}

func (p *Plugin) CreateAttestedNode(ctx context.Context, req *datastorev1.CreateAttestedNodeRequest) (*datastorev1.CreateAttestedNodeResponse, error) {
	if req == nil || req.Node == nil {
		return nil, newCassandraError("invalid request: missing attested node")
	}

	newAttestedNode := &datastorev1.AttestedNode{
		SpiffeId:            req.Node.SpiffeId,
		AttestationDataType: req.Node.AttestationDataType,
		CertSerialNumber:    req.Node.CertSerialNumber,
		CertNotAfter:        req.Node.CertNotAfter,
		NewCertSerialNumber: req.Node.NewCertSerialNumber,
		CanReattest:         req.Node.CanReattest,
		Selectors:           req.Node.Selectors,
	}

	if req.Node.NewCertNotAfter != 0 {
		newAttestedNode.NewCertNotAfter = req.Node.NewCertNotAfter
	}

	createdNode, err := p.createAttestedNode(ctx, newAttestedNode)
	if err != nil {
		return nil, err
	}

	return &datastorev1.CreateAttestedNodeResponse{
		Node: createdNode,
	}, nil
}

func (p *Plugin) createAttestedNode(ctx context.Context, model *datastorev1.AttestedNode) (*datastorev1.AttestedNode, error) {
	createAttestedNodeQuery := `
		INSERT INTO attested_node_entries (
			created_at,
			updated_at,
			spiffe_id,
			attestation_data_type,
			serial_number,
			cert_not_after,
			new_serial_number,
			new_cert_not_after,
			can_reattest,
			agent_version,
			selector_type_value,
			selector_type_value_full,
			banned,
			index_terms
		) VALUES (toTimestamp(now()), toTimestamp(now()), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	var selectorTypeValue []string
	for _, sel := range model.Selectors {
		selectorTypeValue = append(selectorTypeValue, selectorToString(sel))
	}

	selectorIndexes := buildSelectorIndexes(model.Selectors)

	b := p.db.session.Batch(gocql.LoggedBatch)
	b.Consistency(p.db.cfg.WriteConsistency)
	b.Query(
		createAttestedNodeQuery,
		model.GetSpiffeId(),
		model.GetAttestationDataType(),
		model.GetCertSerialNumber(),
		model.GetCertNotAfter(),
		model.GetNewCertSerialNumber(),
		model.GetNewCertNotAfter(),
		model.GetCanReattest(),
		model.GetAgentVersion(),
		"",
		selectorTypeValue,
		model.GetCertSerialNumber() == "",
		selectorIndexes,
	)

	for _, stv := range selectorTypeValue {
		b.Query(createAttestedNodeQuery,
			model.GetSpiffeId(),
			model.GetAttestationDataType(),
			model.GetCertSerialNumber(),
			model.GetCertNotAfter(),
			model.GetNewCertSerialNumber(),
			model.GetNewCertNotAfter(),
			model.GetCanReattest(),
			model.GetAgentVersion(),
			stv,
			selectorTypeValue,
			model.GetCertSerialNumber() == "",
			selectorIndexes,
		)
	}

	if err := b.ExecContext(ctx); err != nil {
		return nil, newWrappedCassandraError(err)
	}

	model.CreatedAt = time.Now().Unix()
	model.UpdatedAt = model.CreatedAt

	err := p.createAttestedNodeEvent(ctx, &datastorev1.AttestedNodeEvent{
		SpiffeId: model.GetSpiffeId(),
	})

	return model, err
}

func (p *Plugin) DeleteAttestedNode(ctx context.Context, req *datastorev1.DeleteAttestedNodeRequest) (*datastorev1.DeleteAttestedNodeResponse, error) {
	if req == nil || req.SpiffeId == "" {
		return nil, status.Error(codes.InvalidArgument, "spiffe id is required")
	}

	attestedNode, err := p.FetchAttestedNode(ctx, &datastorev1.FetchAttestedNodeRequest{
		SpiffeId: req.SpiffeId,
	})
	if err != nil {
		return nil, err
	}
	if attestedNode == nil || attestedNode.Node == nil {
		return nil, status.Error(codes.NotFound, NotFoundErr.Error())
	}

	query := qb.NewDelete().
		From("attested_node_entries").
		Where("spiffe_id", qb.Equals(req.SpiffeId))
	q, _ := query.Build()

	if err := p.db.session.Query(q, req.SpiffeId).Consistency(p.db.cfg.WriteConsistency).ExecContext(ctx); err != nil {
		return nil, newWrappedCassandraError(err)
	}

	err = p.createAttestedNodeEvent(ctx, &datastorev1.AttestedNodeEvent{
		SpiffeId: req.SpiffeId,
	})

	attestedNode.Node.Selectors = nil // we don't want to return selectors on delete, we can make this better by fetching the node without selectors in the first place
	return &datastorev1.DeleteAttestedNodeResponse{
		Node: attestedNode.Node,
	}, err
}

func (p *Plugin) FetchAttestedNode(ctx context.Context, req *datastorev1.FetchAttestedNodeRequest) (*datastorev1.FetchAttestedNodeResponse, error) {
	if req == nil || req.SpiffeId == "" {
		return nil, status.Error(codes.InvalidArgument, "spiffe id is required")
	}

	q := qb.NewSelect().
		Column("spiffe_id").
		Column("attestation_data_type").
		Column("serial_number").
		Column("cert_not_after").
		Column("new_serial_number").
		Column("new_cert_not_after").
		Column("can_reattest").
		Column("selector_type_value_full").
		From("attested_node_entries").
		Where("spiffe_id", qb.Equals(req.SpiffeId)).
		Limit(1)
	query, _ := q.Build()

	var (
		model                 = new(datastorev1.AttestedNode)
		selectorTypeValueFull []string
	)
	if err := p.db.session.Query(query, q.QueryValues()...).Consistency(p.db.cfg.ReadConsistency).ScanContext(ctx,
		&model.SpiffeId,
		&model.AttestationDataType,
		&model.CertSerialNumber,
		&model.CertNotAfter,
		&model.NewCertSerialNumber,
		&model.NewCertNotAfter,
		&model.CanReattest,
		&selectorTypeValueFull,
	); err != nil {
		if errors.Is(err, gocql.ErrNotFound) {
			return nil, nil
		}
		return nil, newWrappedCassandraError(err)
	}

	model.Selectors = selectorStringsToSelectorObjs(selectorTypeValueFull)

	return &datastorev1.FetchAttestedNodeResponse{
		Node: model,
	}, nil
}

func (p *Plugin) ListAttestedNodes(ctx context.Context, req *datastorev1.ListAttestedNodesRequest) (*datastorev1.ListAttestedNodesResponse, error) {
	pager := pages.NewQueryPaginator(req.GetPagination() != nil, req.GetPagination().GetPageSize(), req.GetPagination().GetPageToken())

	if req.BySelectors != nil && len(req.BySelectors.Selectors) == 0 {
		return nil, status.Error(codes.InvalidArgument, "cannot list by empty selectors set")
	}
	var includeExtraCol bool

	q := qb.NewSelect().
		Column("spiffe_id").
		Column("attestation_data_type").
		Column("serial_number").
		Column("cert_not_after").
		Column("new_serial_number").
		Column("new_cert_not_after").
		Column("can_reattest").
		From("attested_node_entries").
		AllowFiltering()

	if req.FetchSelectors {
		q.Column("selector_type_value_full")
	}

	if req.ByBanned {
		if req.BannedValue {
			// The original SQL implementation marks nodes as "banned" by setting
			// their serial number to an empty string. However, since Cassandra
			// does not support filtering with "!=" operator, we add a dedicated
			// "banned" boolean column to simplify queries.
			q.Where("banned", qb.Equals(true))
		} else {
			q.Where("banned", qb.Equals(false))
		}
	}
	if req.ByAttestationType != "" {
		q.Where("attestation_data_type", qb.Equals(req.ByAttestationType))
	}
	if req.ByExpiresBefore > 0 {
		q.Where("cert_not_after", qb.LessThan(req.ByExpiresBefore))
	}
	if req.ByValidAt > 0 {
		q.Where("cert_not_after", qb.GreaterThan(req.ByValidAt))
	}
	if req.ByCanReattest {
		q.Where("can_reattest", qb.Equals(req.CanReattestValue))
	}
	if req.BySelectors != nil {
		includeExtraCol = generateSelectorFilters(req.BySelectors, q)
		if includeExtraCol {
			q.Column("updated_at")
		}
	} else {
		q.Distinct() // No need to fetch multiple rows per node
	}

	query, _ := q.Build()

	cqlQuery := p.db.session.Query(query, q.QueryValues()...)
	cqlQuery.Consistency(p.db.cfg.ReadConsistency)

	cqlQuery = pager.BindToQuery(cqlQuery)

	iter := cqlQuery.IterContext(ctx)
	scanner := iter.Scanner()
	pager.ForIter(iter)

	// we use a hack here that may not be a great idea, but it sure is creative!
	// TODO(tjons): fix!
	attestedNodes := make(map[string]*datastorev1.AttestedNode, iter.NumRows())
	for scanner.Next() {
		var (
			err                   error
			model                 datastorev1.AttestedNode
			selectorTypeValueFull []string

			scanVals = []any{
				&model.SpiffeId,
				&model.AttestationDataType,
				&model.CertSerialNumber,
				&model.CertNotAfter,
				&model.NewCertSerialNumber,
				&model.NewCertNotAfter,
				&model.CanReattest,
			}
		)

		// depending on the input request, we may need to scan different columns,
		// so we'll handle that here by checking the request parameters and scanning
		// accordingly into the correct variables.
		//
		// we will assign the error from scanner.Scan to err, and handle it below
		// to avoid duplicating error handling code.
		if req.FetchSelectors {
			scanVals = append(scanVals, &selectorTypeValueFull)
		}
		if includeExtraCol {
			// we need to include the row-level distinguishing column
			// in some cases to allow filtering on non-static columns
			scanVals = append(scanVals, &model.UpdatedAt)
		}

		if err = scanner.Scan(scanVals...); err != nil {
			return nil, newWrappedCassandraError(err)
		}

		// TODO(tjons): can we avoid having to store these selectors in the intermediary type?
		model.Selectors = selectorStringsToSelectorObjs(selectorTypeValueFull)
		attestedNodes[model.SpiffeId] = &model
	}

	if err := scanner.Err(); err != nil {
		return nil, newWrappedCassandraError(err)
	}

	pager.NextPageToken()

	resp := &datastorev1.ListAttestedNodesResponse{
		Nodes:      slices.Collect(maps.Values(attestedNodes)),
		Pagination: responsePaginationFromPager(pager),
	}

	// if req.Pagination != nil {
	// 	resp.Pagination = &datastore.Pagination{
	// 		PageSize: req.Pagination.PageSize,
	// 	}

	// TODO(tjons): this is really weird, and I'm not sure that this is entirely correct to disable it, because
	// tests pass without it but fail with it because we don't send a "next page" token when there are no more pages.
	// Bizarrely, ListRegistrationEntries tests don't pass without it!

	// peeker := p.db.session.Query(query, q.QueryValues()...)
	// peeker.Consistency(gocql.LocalQuorum)

	// peeker.PageState(pageState)
	// peeker.PageSize(1)
	// peekIter := peeker.IterContext(ctx)
	// if peekIter.NumRows() > 0 {
	// resp.Pagination.Token = base64.URLEncoding.Strict().EncodeToString(pageState)
	// }
	// if err := peekIter.Close(); err != nil {
	// 	return nil, newWrappedCassandraError(err)
	// }
	// }

	return resp, nil
}

var AllTrueAgentMask = &datastorev1.AttestedNodeMask{
	AttestationDataType: true,
	CertSerialNumber:    true,
	CertNotAfter:        true,
	NewCertSerialNumber: true,
	NewCertNotAfter:     true,
	CanReattest:         true,
	AgentVersion:        true,
}

func (p *Plugin) UpdateAttestedNode(ctx context.Context, req *datastorev1.UpdateAttestedNodeRequest) (*datastorev1.UpdateAttestedNodeResponse, error) {
	if req == nil || req.Node == nil {
		return nil, newCassandraError("invalid request: missing attested node")
	}

	existingNodeResp, err := p.FetchAttestedNode(ctx, &datastorev1.FetchAttestedNodeRequest{
		SpiffeId: req.Node.SpiffeId,
	})
	if err != nil {
		return nil, err
	}
	if existingNodeResp.GetNode() == nil {
		return nil, status.Error(codes.NotFound, NotFoundErr.Error())
	}
	existingNode := existingNodeResp.GetNode()

	if req.Mask == nil {
		req.Mask = AllTrueAgentMask
	}

	updateQ := qb.NewUpdate().
		Table("attested_node_entries").
		Where("spiffe_id", qb.Equals(req.Node.SpiffeId))

	var hasWrites bool
	if req.Mask.CertNotAfter {
		existingNode.CertNotAfter = req.Node.CertNotAfter
		updateQ.Set("cert_not_after", req.Node.CertNotAfter)
		hasWrites = true
	}
	if req.Mask.CertSerialNumber { // TODO(tjons): tighten up the field naming and column naming for clarity now that we have like 4 places for the same thing
		existingNode.CertSerialNumber = req.Node.CertSerialNumber
		updateQ.Set("serial_number", req.Node.CertSerialNumber)
		hasWrites = true

		if req.Node.CertSerialNumber == "" {
			// The original SQL implementation marks nodes as "banned" by setting
			// their serial number to an empty string. However, since Cassandra
			// does not support filtering with "!=" operator, we add a dedicated
			// "banned" boolean column to simplify queries.
			updateQ.Set("banned", true)
		} else {
			updateQ.Set("banned", false)
		}
	}
	if req.Mask.NewCertNotAfter {
		existingNode.NewCertNotAfter = req.Node.NewCertNotAfter
		if req.Node.NewCertNotAfter != 0 {
			updateQ.Set("new_cert_not_after", req.Node.NewCertNotAfter)
		} else {
			updateQ.Set("new_cert_not_after", nil)
		}
		hasWrites = true
	}
	if req.Mask.NewCertSerialNumber {
		existingNode.NewCertSerialNumber = req.Node.NewCertSerialNumber
		updateQ.Set("new_serial_number", req.Node.NewCertSerialNumber)
		hasWrites = true
	}
	if req.Mask.CanReattest {
		existingNode.CanReattest = req.Node.CanReattest
		updateQ.Set("can_reattest", req.Node.CanReattest)
		hasWrites = true
	}
	if req.Mask.AgentVersion {
		existingNode.AgentVersion = req.Node.AgentVersion
		updateQ.Set("agent_version", req.Node.AgentVersion)
		hasWrites = true
	}

	if hasWrites {
		q, _ := updateQ.Build()
		if err := p.db.session.Query(q, updateQ.QueryValues()...).Consistency(p.db.cfg.WriteConsistency).ExecContext(ctx); err != nil {
			return nil, newWrappedCassandraError(err)
		}
	}

	err = p.createAttestedNodeEvent(ctx, &datastorev1.AttestedNodeEvent{
		SpiffeId: req.Node.SpiffeId,
	})
	if err != nil {
		return nil, err
	}

	return &datastorev1.UpdateAttestedNodeResponse{
		Node: existingNode,
	}, nil
}

func (p *Plugin) PruneAttestedExpiredNodes(
	ctx context.Context,
	req *datastorev1.PruneAttestedExpiredNodesRequest,
) (*datastorev1.PruneAttestedExpiredNodesResponse, error) {
	if req == nil || req.ExpiresBefore == 0 {
		return nil, newCassandraError("invalid request: missing expired_before timestamp")
	}

	findQ := qb.NewSelect().
		Distinct().
		Column("spiffe_id").
		Column("serial_number").
		From("attested_node_entries").
		Where("cert_not_after", qb.LessThan(req.GetExpiresBefore())).
		Where("can_reattest", qb.Equals(!req.GetIncludeNonReattestable())).
		AllowFiltering()

	query, _ := findQ.Build()
	iter := p.db.session.Query(query, findQ.QueryValues()...).Consistency(p.db.cfg.ReadConsistency).IterContext(ctx)
	scanner := iter.Scanner()

	var spiffeIDs []string
	for scanner.Next() {
		var spiffeID, serialNumber string
		if err := scanner.Scan(&spiffeID, &serialNumber); err != nil {
			return nil, newWrappedCassandraError(err)
		}

		// since Cassandra doesn't support `!=` in SELECT statments, we filter the
		// banned entries here. SPIRE marks nodes as banned by setting their
		// serial number to an empty string.
		if len(serialNumber) == 0 {
			continue
		}
		spiffeIDs = append(spiffeIDs, spiffeID)
	}
	if err := scanner.Err(); err != nil {
		return nil, newWrappedCassandraError(err)
	}

	for _, spiffeID := range spiffeIDs {
		query := qb.NewDelete().
			From("attested_node_entries").
			Where("spiffe_id", qb.Equals(spiffeID))
		q, _ := query.Build()
		if err := p.db.session.Query(q, spiffeID).Consistency(p.db.cfg.WriteConsistency).ExecContext(ctx); err != nil {
			return nil, newWrappedCassandraError(err)
		}

		if err := p.createAttestedNodeEvent(ctx, &datastorev1.AttestedNodeEvent{
			SpiffeId: spiffeID,
		}); err != nil {
			return nil, err
		}
	}

	return &datastorev1.PruneAttestedExpiredNodesResponse{}, nil
}

func (p *Plugin) GetNodeSelectors(ctx context.Context, req *datastorev1.GetNodeSelectorsRequest) (*datastorev1.GetNodeSelectorsResponse, error) {
	if req == nil || req.SpiffeId == "" {
		return nil, status.Error(codes.InvalidArgument, "spiffe id is required")
	}

	q := qb.NewSelect().
		Column("selector_type_value_full").
		From("attested_node_entries").
		Where("spiffe_id", qb.Equals(req.SpiffeId)).
		Limit(1)
	query, _ := q.Build()

	var selectorTypeValueFull []string
	if err := p.db.session.Query(query, req.SpiffeId).Consistency(p.db.cfg.ReadConsistency).ScanContext(ctx, &selectorTypeValueFull); err != nil {
		if !errors.Is(err, gocql.ErrNotFound) {
			return nil, newWrappedCassandraError(err)
		}

		return nil, nil
	}

	return &datastorev1.GetNodeSelectorsResponse{
		Selectors: selectorStringsToSelectorObjs(selectorTypeValueFull),
	}, nil
}

func (p *Plugin) ListNodeSelectors(ctx context.Context, req *datastorev1.ListNodeSelectorsRequest) (*datastorev1.ListNodeSelectorsResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}

	q := qb.NewSelect().
		Distinct().
		Column("spiffe_id").
		Column("selector_type_value_full").
		From("attested_node_entries").
		AllowFiltering()

	if req.ValidAt != 0 {
		q.Where("cert_not_after", qb.GreaterThan(req.ValidAt))
	}

	query, _ := q.Build()

	iter := p.db.session.Query(query, q.QueryValues()...).Consistency(p.db.cfg.ReadConsistency).IterContext(ctx)
	scanner := iter.Scanner()
	selectorEntries := make(map[string]*datastorev1.NodeSelectorEntry, iter.NumRows())

	for scanner.Next() {
		var (
			spiffeID string
			stvList  []string
		)
		if err := scanner.Scan(&spiffeID, &stvList); err != nil {
			return nil, newWrappedCassandraError(err)
		}

		selectorEntries[spiffeID] = &datastorev1.NodeSelectorEntry{
			SpiffeId:  spiffeID,
			Selectors: selectorStringsToSelectorObjs(stvList),
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, newWrappedCassandraError(err)
	}

	return &datastorev1.ListNodeSelectorsResponse{
		Selectors: slices.Collect(maps.Values(selectorEntries)),
	}, nil
}

func (p *Plugin) SetNodeSelectors(ctx context.Context, req *datastorev1.SetNodeSelectorsRequest) (*datastorev1.SetNodeSelectorsResponse, error) {
	if req == nil || req.SpiffeId == "" {
		return nil, status.Error(codes.InvalidArgument, "spiffe id is required")
	}

	nodeResp, err := p.FetchAttestedNode(ctx, &datastorev1.FetchAttestedNodeRequest{
		SpiffeId: req.SpiffeId,
	})
	if err != nil {
		return nil, err
	}
	node := nodeResp.GetNode()

	var existingSelectors []*datastorev1.Selector
	if node != nil {
		existingSelectors = node.Selectors
	}

	if err = p.setNodeSelectors(ctx, req.SpiffeId, req.Selectors, existingSelectors); err != nil {
		return nil, err
	}

	return &datastorev1.SetNodeSelectorsResponse{}, p.createAttestedNodeEvent(ctx, &datastorev1.AttestedNodeEvent{
		SpiffeId: req.SpiffeId,
	})
}

func (p *Plugin) setNodeSelectors(ctx context.Context, spiffeID string, newSelectors, existingSelectors []*datastorev1.Selector) error {
	selectorsToDelete := make(map[string]struct{}, len(existingSelectors))
	selectorsToInsert := make(map[string]struct{}, len(newSelectors))
	for _, sel := range existingSelectors {
		key := selectorToString(sel)
		selectorsToDelete[key] = struct{}{}
	}

	for _, sel := range newSelectors {
		key := selectorToString(sel)
		delete(selectorsToDelete, key)
		selectorsToInsert[key] = struct{}{}
	}

	if len(selectorsToDelete) == 0 && len(selectorsToInsert) == 0 {
		return nil
	}

	b := p.db.session.Batch(gocql.LoggedBatch)
	b.Consistency(p.db.cfg.WriteConsistency)

	for sel := range selectorsToDelete {
		deleteQuery := qb.NewDelete().
			From("attested_node_entries").
			Where("spiffe_id", qb.Equals(spiffeID)).
			Where("selector_type_value", qb.Equals(sel))
		deleteCQL, _ := deleteQuery.Build()

		b.Query(deleteCQL, deleteQuery.QueryValues()...)
	}

	newStvFull := make([]string, 0)
	for sel := range selectorsToInsert {
		newStvFull = append(newStvFull, sel)
	}

	for i := range newStvFull {
		setStvQuery := qb.NewInsert().
			Into("attested_node_entries").
			Columns(
				"spiffe_id",
				"selector_type_value",
				"selector_type_value_full",
			).
			Values(
				spiffeID,
				newStvFull[i],
				newStvFull,
			)
		q, _ := setStvQuery.Build()

		b.Query(q, setStvQuery.QueryValues()...)
	}

	if len(newStvFull) == 0 {
		// If there are no selectors left, we still need to update the
		// selector_type_value_full to an empty list
		deletePartitionList := qb.NewDelete().
			Column("selector_type_value_full").
			From("attested_node_entries").
			Where("spiffe_id", qb.Equals(spiffeID))
		q, _ := deletePartitionList.Build()

		b.Query(q, deletePartitionList.QueryValues()...)
	}

	if err := b.ExecContext(ctx); err != nil {
		return newWrappedCassandraError(err)
	}

	return nil
}
