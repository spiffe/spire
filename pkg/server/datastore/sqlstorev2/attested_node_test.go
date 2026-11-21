package sqlstorev2

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/pkg/server/datastore"
	v1 "github.com/spiffe/spire/pkg/server/datastore/sqlstore"
	"github.com/spiffe/spire/pkg/server/datastore/sqltest"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestNodeQueriesMatchV1(t *testing.T) {
	ctx := context.Background()
	hcl := nodeTestConfig(t)

	log, _ := test.NewNullLogger()
	dsV1 := v1.New(log)
	require.NoError(t, dsV1.Configure(ctx, hcl))
	t.Cleanup(func() { dsV1.Close() })
	dsV2 := New(log)
	require.NoError(t, dsV2.Configure(ctx, hcl))
	t.Cleanup(func() { dsV2.Close() })

	now := time.Now().Truncate(time.Second)
	sel := func(t, v string) *common.Selector { return &common.Selector{Type: t, Value: v} }
	var ids []string
	for i := range 60 {
		id := fmt.Sprintf("spiffe://example.org/node/%02d", i)
		ids = append(ids, id)
		serial := "serial"
		if i%7 == 0 {
			serial = ""
		}
		node := &common.AttestedNode{
			SpiffeId:            id,
			AttestationDataType: fmt.Sprintf("t%d", i%3),
			CertSerialNumber:    serial,
			CertNotAfter:        now.Add(time.Duration(i%4-2) * time.Hour).Unix(),
			CanReattest:         i%2 == 0,
		}
		if i%4 == 1 {
			node.NewCertSerialNumber = fmt.Sprintf("new-%d", i)
			node.NewCertNotAfter = now.Add(time.Duration(i) * time.Hour).Unix()
			node.AgentVersion = fmt.Sprintf("1.%d.0", i)
		}
		_, err := dsV2.CreateAttestedNode(ctx, node)
		require.NoError(t, err)
		selectors := []*common.Selector{sel("common", "x"), sel("g", fmt.Sprint(i%3)), sel("r", fmt.Sprint(i%2))}
		switch i % 10 {
		case 0:
			selectors = append(selectors, sel("case", "Mixed"))
		case 5:
			selectors = append(selectors, sel("case", "mixed"))
		}
		require.NoError(t, dsV2.SetNodeSelectors(ctx, id, selectors))
	}

	selectorSets := map[string][]*common.Selector{
		"one":        {sel("g", "1")},
		"two":        {sel("common", "x"), sel("g", "1")},
		"wide":       {sel("common", "x"), sel("g", "1"), sel("r", "0"), sel("r", "1"), sel("case", "mixed")},
		"exact_case": {sel("common", "x"), sel("g", "0"), sel("r", "0"), sel("case", "Mixed")},
		"duplicates": {sel("g", "1"), sel("g", "1"), sel("common", "x")},
		"no_match":   {sel("case", "MIXED")},
		"both_cases": {sel("common", "x"), sel("case", "Mixed"), sel("case", "mixed")},
	}
	matches := []datastore.MatchBehavior{datastore.MatchAny, datastore.Superset, datastore.Subset, datastore.Exact}

	// A few absolute results, so matching empty results cannot pass.
	all, err := listAllNodes(ctx, dsV2, &datastore.ListAttestedNodesRequest{FetchSelectors: true})
	require.NoError(t, err)
	require.Len(t, all, 60)
	spiretest.AssertProtoEqual(t, &common.AttestedNode{
		SpiffeId: ids[5], AttestationDataType: "t2", CertSerialNumber: "serial", CertNotAfter: now.Add(-time.Hour).Unix(),
		NewCertSerialNumber: "new-5", NewCertNotAfter: now.Add(5 * time.Hour).Unix(), AgentVersion: "1.5.0",
		Selectors: []*common.Selector{sel("common", "x"), sel("g", "2"), sel("r", "1"), sel("case", "mixed")},
	}, all[5])
	anyG1, err := dsV2.CountAttestedNodes(ctx, &datastore.CountAttestedNodesRequest{BySelectorMatch: &datastore.BySelectors{Match: datastore.MatchAny, Selectors: selectorSets["one"]}})
	require.NoError(t, err)
	require.EqualValues(t, 20, anyG1)
	supersetIDs := func(set string) []string {
		nodes, err := listAllNodes(ctx, dsV2, &datastore.ListAttestedNodesRequest{BySelectorMatch: &datastore.BySelectors{Match: datastore.Superset, Selectors: selectorSets[set]}})
		require.NoError(t, err)
		return nodeIDs(nodes)
	}
	var g1, bothCases []string
	for i := 1; i < 60; i += 3 {
		g1 = append(g1, ids[i])
	}
	if TestDialect == "mysql" { // MySQL collations ignore case.
		for i := 0; i < 60; i += 5 {
			bothCases = append(bothCases, ids[i])
		}
	}
	require.Equal(t, g1, supersetIDs("duplicates"))
	require.ElementsMatch(t, bothCases, supersetIDs("both_cases"))

	banned, unbanned, reattest := true, false, true
	filters := map[string]datastore.ListAttestedNodesRequest{
		"none":           {},
		"type":           {ByAttestationType: "t1"},
		"banned":         {ByBanned: &banned},
		"unbanned":       {ByBanned: &unbanned},
		"reattest":       {ByCanReattest: &reattest},
		"expires_before": {ByExpiresBefore: now},
		"valid_at":       {ValidAt: now},
		"spiffe_ids":     {BySpiffeIDs: []string{ids[3], ids[4], ids[10], ids[59], "spiffe://example.org/missing"}},
	}
	for setName, set := range selectorSets {
		for _, match := range matches {
			filters[fmt.Sprintf("match%d_%s", match, setName)] = datastore.ListAttestedNodesRequest{BySelectorMatch: &datastore.BySelectors{Match: match, Selectors: set}}
			filters[fmt.Sprintf("match%d_%s_unbanned", match, setName)] = datastore.ListAttestedNodesRequest{ByBanned: &unbanned, BySelectorMatch: &datastore.BySelectors{Match: match, Selectors: set}}
		}
	}

	for name, filter := range filters {
		for _, pageSize := range []int32{0, 7} {
			for _, fetchSelectors := range []bool{false, true} {
				newReq := func() *datastore.ListAttestedNodesRequest {
					req := filter
					req.FetchSelectors = fetchSelectors
					if pageSize > 0 {
						req.Pagination = &datastore.Pagination{PageSize: pageSize}
					}
					return &req
				}
				t.Run(fmt.Sprintf("%s/page=%d/selectors=%t", name, pageSize, fetchSelectors), func(t *testing.T) {
					// Pages may differ: v1 fills a page before dropping Subset and
					// Exact misses, v2 fills it with matches only.
					nodesV1, err := listAllNodes(ctx, dsV1, newReq())
					require.NoError(t, err)
					nodesV2, err := listAllNodes(ctx, dsV2, newReq())
					require.NoError(t, err)
					spiretest.AssertProtoListEqual(t, sortSelectors(nodesV1), sortSelectors(nodesV2))

					if len(filter.BySpiffeIDs) > 0 || !filter.ValidAt.IsZero() || pageSize > 0 {
						return
					}
					countReq := &datastore.CountAttestedNodesRequest{
						ByAttestationType: filter.ByAttestationType,
						ByBanned:          filter.ByBanned,
						ByCanReattest:     filter.ByCanReattest,
						ByExpiresBefore:   filter.ByExpiresBefore,
						BySelectorMatch:   filter.BySelectorMatch,
						FetchSelectors:    fetchSelectors,
					}
					countV1, err := dsV1.CountAttestedNodes(ctx, countReq)
					require.NoError(t, err)
					countV2, err := dsV2.CountAttestedNodes(ctx, countReq)
					require.NoError(t, err)
					require.Equal(t, countV1, countV2)
				})
			}
		}
	}
}

func TestSubsetAndExactPagesHoldMatchesOnly(t *testing.T) {
	ds := newNodeTestPlugin(t)
	ctx := context.Background()
	var matching []string
	for i := range 8 {
		id := fmt.Sprintf("spiffe://example.org/node/%d", i)
		_, err := ds.CreateAttestedNode(ctx, &common.AttestedNode{SpiffeId: id, CertNotAfter: 1})
		require.NoError(t, err)
		selectors := []*common.Selector{{Type: "a", Value: "1"}}
		if i%3 == 0 || i == 4 {
			matching = append(matching, id)
		} else {
			selectors = append(selectors, &common.Selector{Type: "b", Value: "1"})
		}
		require.NoError(t, ds.SetNodeSelectors(ctx, id, selectors))
	}

	for _, match := range []datastore.MatchBehavior{datastore.Subset, datastore.Exact} {
		req := &datastore.ListAttestedNodesRequest{
			Pagination:      &datastore.Pagination{PageSize: 2},
			BySelectorMatch: &datastore.BySelectors{Match: match, Selectors: []*common.Selector{{Type: "a", Value: "1"}}},
		}
		var pages [][]string
		for {
			resp, err := ds.ListAttestedNodes(ctx, req)
			require.NoError(t, err)
			if len(resp.Nodes) == 0 {
				break
			}
			pages = append(pages, nodeIDs(resp.Nodes))
			req.Pagination = resp.Pagination
		}
		require.Equal(t, [][]string{matching[:2], matching[2:]}, pages, "match %d", match)
	}
}

func TestCreateDuplicateAttestedNode(t *testing.T) {
	ds := newNodeTestPlugin(t)
	ctx := context.Background()
	node := &common.AttestedNode{SpiffeId: "spiffe://example.org/node", CertNotAfter: 1}
	_, err := ds.CreateAttestedNode(ctx, node)
	require.NoError(t, err)
	_, err = ds.CreateAttestedNode(ctx, node)
	require.Equal(t, codes.AlreadyExists, status.Code(err), err)

	events, err := ds.ListAttestedNodeEvents(ctx, &datastore.ListAttestedNodeEventsRequest{})
	require.NoError(t, err)
	require.Equal(t, []string{node.SpiffeId}, eventSpiffeIDs(events))
}

func TestListAttestedNodesValidation(t *testing.T) {
	ds := newNodeTestPlugin(t)
	ctx := context.Background()
	selectors := []*common.Selector{{Type: "a", Value: "b"}}

	for _, tt := range []struct {
		name string
		req  *datastore.ListAttestedNodesRequest
		err  string
	}{
		{"page size zero", &datastore.ListAttestedNodesRequest{Pagination: &datastore.Pagination{}}, "rpc error: code = InvalidArgument desc = cannot paginate with pagesize = 0"},
		{"bad token", &datastore.ListAttestedNodesRequest{Pagination: &datastore.Pagination{PageSize: 1, Token: "x"}}, "rpc error: code = InvalidArgument desc = could not parse token 'x'"},
		{"empty selectors", &datastore.ListAttestedNodesRequest{BySelectorMatch: &datastore.BySelectors{}}, "rpc error: code = InvalidArgument desc = cannot list by empty selectors set"},
		{"bad match", &datastore.ListAttestedNodesRequest{BySelectorMatch: &datastore.BySelectors{Match: 99, Selectors: selectors}}, "rpc error: code = InvalidArgument desc = unhandled match behavior 99"},
		{"bad match with selectors", &datastore.ListAttestedNodesRequest{FetchSelectors: true, BySelectorMatch: &datastore.BySelectors{Match: 99, Selectors: selectors}}, "rpc error: code = InvalidArgument desc = unhandled match behavior 99"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ds.ListAttestedNodes(ctx, tt.req)
			require.EqualError(t, err, tt.err)
		})
	}

	_, err := ds.CountAttestedNodes(ctx, &datastore.CountAttestedNodesRequest{BySelectorMatch: &datastore.BySelectors{Match: 99, Selectors: selectors}})
	require.EqualError(t, err, "rpc error: code = InvalidArgument desc = unhandled match behavior 99")
}

func TestFetchAttestedNodeEvent(t *testing.T) {
	ds := newNodeTestPlugin(t)
	ctx := context.Background()
	require.NoError(t, ds.CreateAttestedNodeEventForTesting(ctx, &datastore.AttestedNodeEvent{EventID: 7, SpiffeID: "spiffe://example.org/node"}))

	event, err := ds.FetchAttestedNodeEvent(ctx, 7)
	require.NoError(t, err)
	require.Equal(t, &datastore.AttestedNodeEvent{EventID: 7, SpiffeID: "spiffe://example.org/node"}, event)

	_, err = ds.FetchAttestedNodeEvent(ctx, 42)
	spiretest.RequireGRPCStatus(t, err, codes.NotFound, "datastore-sql: record not found")
}

func TestPruneAttestedExpiredNodesWritesEvents(t *testing.T) {
	ds := newNodeTestPlugin(t)
	ctx := context.Background()
	node := &common.AttestedNode{SpiffeId: "spiffe://example.org/node", CertSerialNumber: "1", CertNotAfter: 1, CanReattest: true}
	_, err := ds.CreateAttestedNode(ctx, node)
	require.NoError(t, err)

	require.NoError(t, ds.PruneAttestedExpiredNodes(ctx, time.Now(), false, 0))

	resp, err := ds.ListAttestedNodeEvents(ctx, &datastore.ListAttestedNodeEventsRequest{})
	require.NoError(t, err)
	require.Equal(t, []string{node.SpiffeId, node.SpiffeId}, eventSpiffeIDs(resp), "create and prune events")
}

func TestFailedNodeWritesLeaveNoEvent(t *testing.T) {
	ds := newNodeTestPlugin(t)
	ctx := context.Background()

	_, err := ds.UpdateAttestedNode(ctx, nil, nil)
	require.EqualError(t, err, "datastore-sql: invalid request: missing attested node")
	_, err = ds.UpdateAttestedNode(ctx, &common.AttestedNode{SpiffeId: "spiffe://example.org/missing"}, nil)
	spiretest.RequireGRPCStatus(t, err, codes.NotFound, "datastore-sql: record not found")
	_, err = ds.DeleteAttestedNode(ctx, "spiffe://example.org/missing")
	spiretest.RequireGRPCStatus(t, err, codes.NotFound, "datastore-sql: record not found")

	resp, err := ds.ListAttestedNodeEvents(ctx, &datastore.ListAttestedNodeEventsRequest{})
	require.NoError(t, err)
	require.Empty(t, resp.Events)
}

func TestJoinTokenAttestedNodesAreNotDeleted(t *testing.T) {
	ds := newNodeTestPlugin(t)
	ctx := context.Background()
	joinToken := &common.AttestedNode{SpiffeId: "spiffe://example.org/spire/agent/join_token/x", AttestationDataType: "join_token", CertSerialNumber: "1", CertNotAfter: 1}
	other := &common.AttestedNode{SpiffeId: "spiffe://example.org/spire/agent/x509pop/x", AttestationDataType: "x509pop", CertSerialNumber: "1", CertNotAfter: 1}
	untyped := &common.AttestedNode{SpiffeId: "spiffe://example.org/spire/agent/untyped/x", CertSerialNumber: "1", CertNotAfter: 1}
	for _, node := range []*common.AttestedNode{joinToken, other, untyped} {
		_, err := ds.CreateAttestedNode(ctx, node)
		require.NoError(t, err)
	}
	require.NoError(t, ds.RawExec("UPDATE attested_node_entries SET data_type = NULL WHERE spiffe_id = '"+untyped.SpiffeId+"'"))

	_, err := ds.DeleteAttestedNode(ctx, joinToken.SpiffeId)
	spiretest.RequireGRPCStatus(t, err, codes.Unimplemented, "datastore-sql: deleting join token attested nodes is not implemented")

	// Prune skips the join token node instead of failing the batch on it.
	require.NoError(t, ds.PruneAttestedExpiredNodes(ctx, time.Now(), true, 0))
	resp, err := ds.ListAttestedNodes(ctx, &datastore.ListAttestedNodesRequest{})
	require.NoError(t, err)
	require.Equal(t, []string{joinToken.SpiffeId}, nodeIDs(resp.Nodes))

	events, err := ds.ListAttestedNodeEvents(ctx, &datastore.ListAttestedNodeEventsRequest{})
	require.NoError(t, err)
	require.ElementsMatch(t, []string{joinToken.SpiffeId, other.SpiffeId, untyped.SpiffeId, other.SpiffeId, untyped.SpiffeId}, eventSpiffeIDs(events), "no event for the refused delete")
}

func TestTolerateStaleReadsUseReadOnlyConnection(t *testing.T) {
	ctx := context.Background()
	const id = "spiffe://example.org/node"
	rwPath := sqlitePath(t)
	roPath := sqlitePath(t)

	ro := newSQLitePlugin(t)
	configure(t, ro, fmt.Sprintf("database_type = \"sqlite3\"\nconnection_string = %q\n", roPath))
	require.NoError(t, ro.SetNodeSelectors(ctx, id, []*common.Selector{{Type: "db", Value: "ro"}}))

	ds := newSQLitePlugin(t)
	ds.dialectFor = func(databaseType string, log logrus.FieldLogger) (dialect, error) {
		dia, err := newDialect(databaseType, log)
		return readOnlyToROConnStringDialect{dia}, err
	}
	configure(t, ds, fmt.Sprintf("database_type = \"sqlite3\"\nconnection_string = %q\nro_connection_string = %q\n", rwPath, roPath))
	require.NoError(t, ds.SetNodeSelectors(ctx, id, []*common.Selector{{Type: "db", Value: "rw"}}))

	for _, tt := range []struct {
		consistency datastore.DataConsistency
		expected    string
	}{
		{datastore.RequireCurrent, "rw"},
		{datastore.TolerateStale, "ro"},
	} {
		expected := []*common.Selector{{Type: "db", Value: tt.expected}}
		selectors, err := ds.GetNodeSelectors(ctx, id, tt.consistency)
		require.NoError(t, err)
		spiretest.AssertProtoListEqual(t, expected, selectors)

		listed, err := ds.ListNodeSelectors(ctx, &datastore.ListNodeSelectorsRequest{DataConsistency: tt.consistency})
		require.NoError(t, err)
		spiretest.AssertProtoListEqual(t, expected, listed.Selectors[id])

		events, err := ds.ListAttestedNodeEvents(ctx, &datastore.ListAttestedNodeEventsRequest{DataConsistency: tt.consistency})
		require.NoError(t, err)
		require.Len(t, events.Events, 1)
	}
}

func TestNodeReadsNullColumns(t *testing.T) {
	ds := newNodeTestPlugin(t)
	ctx := context.Background()
	node := &common.AttestedNode{SpiffeId: "spiffe://example.org/node", AttestationDataType: "t", CertSerialNumber: "1", CertNotAfter: 1, CanReattest: true, AgentVersion: "1.0.0"}
	_, err := ds.CreateAttestedNode(ctx, node)
	require.NoError(t, err)
	require.NoError(t, ds.SetNodeSelectors(ctx, node.SpiffeId, []*common.Selector{{Type: "a", Value: "1"}}))
	require.NoError(t, ds.RawExec("UPDATE attested_node_entries SET can_reattest = NULL, agent_version = NULL, new_serial_number = NULL, expires_at = NULL"))
	require.NoError(t, ds.RawExec("UPDATE node_resolver_map_entries SET type = NULL, value = NULL"))

	selectors, err := ds.GetNodeSelectors(ctx, node.SpiffeId, datastore.RequireCurrent)
	require.NoError(t, err)
	spiretest.AssertProtoListEqual(t, []*common.Selector{{}}, selectors)
	listed, err := ds.ListNodeSelectors(ctx, &datastore.ListNodeSelectorsRequest{})
	require.NoError(t, err)
	spiretest.AssertProtoListEqual(t, []*common.Selector{{}}, listed.Selectors[node.SpiffeId])

	// CertNotAfter is 0 for a NULL expires_at, and a selector with a NULL type
	// is left out, as in v1.
	expected := &common.AttestedNode{SpiffeId: node.SpiffeId, AttestationDataType: "t", CertSerialNumber: "1"}
	for _, fetchSelectors := range []bool{false, true} {
		resp, err := ds.ListAttestedNodes(ctx, &datastore.ListAttestedNodesRequest{FetchSelectors: fetchSelectors})
		require.NoError(t, err)
		spiretest.AssertProtoListEqual(t, []*common.AttestedNode{expected}, resp.Nodes)
	}
	fetched, err := ds.FetchAttestedNode(ctx, node.SpiffeId)
	require.NoError(t, err)
	spiretest.AssertProtoEqual(t, expected, fetched)
}

func newNodeTestPlugin(t *testing.T) *Plugin {
	hcl := nodeTestConfig(t)
	log, _ := test.NewNullLogger()
	ds := New(log)
	t.Cleanup(func() { require.NoError(t, ds.Close()) })
	configure(t, ds, hcl)
	return ds
}

// nodeTestConfig returns the configuration of an empty database: the external
// one when configured, and a new SQLite file otherwise.
func nodeTestConfig(t *testing.T) string {
	if TestDialect != "" {
		sqltest.WipeDatabase(t, TestDialect, TestConnString)
		return fmt.Sprintf("database_type = %q\nconnection_string = %q\n", TestDialect, TestConnString)
	}
	return fmt.Sprintf("database_type = %q\nconnection_string = %q\n", "sqlite3", sqlitePath(t))
}

// listAllNodes follows the request's pagination, if any, to the last page.
func listAllNodes(ctx context.Context, ds datastore.DataStore, req *datastore.ListAttestedNodesRequest) ([]*common.AttestedNode, error) {
	var nodes []*common.AttestedNode
	for {
		resp, err := ds.ListAttestedNodes(ctx, req)
		if err != nil {
			return nil, err
		}
		nodes = append(nodes, resp.Nodes...)
		if resp.Pagination == nil || resp.Pagination.Token == "" {
			return nodes, nil
		}
		req.Pagination = resp.Pagination
	}
}

// sortSelectors orders each node's selectors, whose order neither datastore
// guarantees.
func sortSelectors(nodes []*common.AttestedNode) []*common.AttestedNode {
	for _, node := range nodes {
		slices.SortFunc(node.Selectors, func(a, b *common.Selector) int {
			return cmp.Or(cmp.Compare(a.Type, b.Type), cmp.Compare(a.Value, b.Value))
		})
	}
	return nodes
}

func nodeIDs(nodes []*common.AttestedNode) []string {
	ids := make([]string, 0, len(nodes))
	for _, node := range nodes {
		ids = append(ids, node.SpiffeId)
	}
	return ids
}

func eventSpiffeIDs(resp *datastore.ListAttestedNodeEventsResponse) []string {
	ids := make([]string, 0, len(resp.Events))
	for _, event := range resp.Events {
		ids = append(ids, event.SpiffeID)
	}
	return ids
}
