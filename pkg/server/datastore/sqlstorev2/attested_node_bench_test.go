package sqlstorev2

import (
	"cmp"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/pkg/server/datastore"
	v1 "github.com/spiffe/spire/pkg/server/datastore/sqlstore"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/stretchr/testify/require"
)

var benchVerified bool

// BenchmarkAttestedNodes compares v1's hand-written node queries with v2's on
// one seeded database, walking every page. It uses SQLite unless BENCH_DB_TYPE
// and BENCH_DB_CONN are set; BENCH_NODES sets the node count (default 10000).
func BenchmarkAttestedNodes(b *testing.B) {
	ctx := context.Background()
	n, err := strconv.Atoi(cmp.Or(os.Getenv("BENCH_NODES"), "10000"))
	require.NoError(b, err)

	dbType := cmp.Or(os.Getenv("BENCH_DB_TYPE"), "sqlite3")
	conn := os.Getenv("BENCH_DB_CONN")
	if dbType == "sqlite3" && conn == "" {
		conn = filepath.ToSlash(filepath.Join(b.TempDir(), "bench.sqlite3"))
	}
	hcl := fmt.Sprintf("database_type = %q\nconnection_string = %q\n", dbType, conn)

	// v1 opens the database first, as an existing deployment would.
	log, _ := test.NewNullLogger()
	log.SetLevel(logrus.ErrorLevel)
	dsV1 := v1.New(log)
	require.NoError(b, dsV1.Configure(ctx, hcl))
	b.Cleanup(func() { dsV1.Close() })

	dsV2 := New(log)
	require.NoError(b, dsV2.Configure(ctx, hcl))
	b.Cleanup(func() { dsV2.Close() })
	seedBenchNodes(b, dsV2, n)

	sel := func(t, v string) *common.Selector { return &common.Selector{Type: t, Value: v} }
	page := &datastore.Pagination{PageSize: 1000}
	ids := make([]string, 0, 100)
	for i := range 100 {
		ids = append(ids, benchNodeID(i*(n/100)))
	}

	lists := []struct {
		name string
		req  func() *datastore.ListAttestedNodesRequest
	}{
		{"page", func() *datastore.ListAttestedNodesRequest {
			return &datastore.ListAttestedNodesRequest{Pagination: clonePage(page)}
		}},
		{"page_selectors", func() *datastore.ListAttestedNodesRequest {
			return &datastore.ListAttestedNodesRequest{Pagination: clonePage(page), FetchSelectors: true}
		}},
		{"all_selectors_valid", func() *datastore.ListAttestedNodesRequest {
			return &datastore.ListAttestedNodesRequest{FetchSelectors: true, ValidAt: time.Now()}
		}},
		{"by_100_ids", func() *datastore.ListAttestedNodesRequest {
			return &datastore.ListAttestedNodesRequest{BySpiffeIDs: ids, FetchSelectors: true}
		}},
		{"filters_page", func() *datastore.ListAttestedNodesRequest {
			banned := false
			return &datastore.ListAttestedNodesRequest{Pagination: clonePage(page), ByAttestationType: "t1", ByBanned: &banned, ValidAt: time.Now()}
		}},
		{"match_any", func() *datastore.ListAttestedNodesRequest {
			return &datastore.ListAttestedNodesRequest{Pagination: clonePage(page), FetchSelectors: true, BySelectorMatch: &datastore.BySelectors{
				Match: datastore.MatchAny, Selectors: []*common.Selector{sel("g100", "1"), sel("g100", "2")},
			}}
		}},
		{"superset", func() *datastore.ListAttestedNodesRequest {
			return &datastore.ListAttestedNodesRequest{Pagination: clonePage(page), FetchSelectors: true, BySelectorMatch: &datastore.BySelectors{
				Match: datastore.Superset, Selectors: []*common.Selector{sel("common", "x"), sel("g10", "1"), sel("region", "1")},
			}}
		}},
		{"subset", func() *datastore.ListAttestedNodesRequest {
			return &datastore.ListAttestedNodesRequest{Pagination: clonePage(page), FetchSelectors: true, BySelectorMatch: &datastore.BySelectors{
				Match: datastore.Subset, Selectors: []*common.Selector{sel("common", "x"), sel("g10", "1"), sel("g100", "1"), sel("g100", "11"), sel("region", "0"), sel("region", "1")},
			}}
		}},
		{"exact", func() *datastore.ListAttestedNodesRequest {
			return &datastore.ListAttestedNodesRequest{Pagination: clonePage(page), FetchSelectors: true, BySelectorMatch: &datastore.BySelectors{
				Match: datastore.Exact, Selectors: []*common.Selector{sel("common", "x"), sel("g10", "1"), sel("g100", "1"), sel("region", "1")},
			}}
		}},
	}

	impls := []struct {
		name string
		ds   datastore.DataStore
	}{{"v1", dsV1}, {"v2", dsV2}}

	// Verifies once per process (the function runs once per -test.count);
	// BENCH_VERIFY=0 skips it.
	verify := !benchVerified && os.Getenv("BENCH_VERIFY") != "0"
	benchVerified = true

	for _, l := range lists {
		// Both implementations must return the same nodes before their speed
		// is compared.
		if verify {
			r1, err := listAllNodes(ctx, dsV1, l.req())
			require.NoError(b, err)
			r2, err := listAllNodes(ctx, dsV2, l.req())
			require.NoError(b, err)
			require.Equal(b, nodeIDs(r1), nodeIDs(r2), l.name)
			require.Equal(b, selectorCount(r1), selectorCount(r2), l.name)
		}

		for _, impl := range impls {
			b.Run("case="+l.name+"/impl="+impl.name, func(b *testing.B) {
				for b.Loop() {
					if _, err := listAllNodes(ctx, impl.ds, l.req()); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}

	counts := []struct {
		name string
		req  *datastore.CountAttestedNodesRequest
	}{
		{"count_unbanned", &datastore.CountAttestedNodesRequest{ByBanned: new(bool), FetchSelectors: true}},
		{"count_superset", &datastore.CountAttestedNodesRequest{FetchSelectors: true, BySelectorMatch: &datastore.BySelectors{
			Match: datastore.Superset, Selectors: []*common.Selector{sel("g10", "1"), sel("region", "1")},
		}}},
	}
	for _, c := range counts {
		if verify {
			c1, err := dsV1.CountAttestedNodes(ctx, c.req)
			require.NoError(b, err)
			c2, err := dsV2.CountAttestedNodes(ctx, c.req)
			require.NoError(b, err)
			require.Equal(b, c1, c2, c.name)
		}

		for _, impl := range impls {
			b.Run("case="+c.name+"/impl="+impl.name, func(b *testing.B) {
				for b.Loop() {
					if _, err := impl.ds.CountAttestedNodes(ctx, c.req); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}

	for _, impl := range impls {
		b.Run("case=list_node_selectors/impl="+impl.name, func(b *testing.B) {
			for b.Loop() {
				if _, err := impl.ds.ListNodeSelectors(ctx, &datastore.ListNodeSelectorsRequest{ValidAt: time.Now()}); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run("case=get_node_selectors/impl="+impl.name, func(b *testing.B) {
			for b.Loop() {
				if _, err := impl.ds.GetNodeSelectors(ctx, benchNodeID(n/2), datastore.RequireCurrent); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// seedBenchNodes fills the node tables with n nodes, each with the selectors
// common:x, g10:<i%10>, g100:<i%100> and region:<i%3>; odd nodes are valid. A
// database already seeded that way is reused.
func seedBenchNodes(b *testing.B, ds *Plugin, n int) {
	db := ds.db.DB
	var have, valid int64
	require.NoError(b, db.Model(&AttestedNode{}).Count(&have).Error)
	require.NoError(b, db.Model(&AttestedNode{}).Where("expires_at > ?", time.Now()).Count(&valid).Error)
	if have == int64(n) && valid == int64(n/2) {
		return
	}
	require.NoError(b, db.Where("1 = 1").Delete(&NodeSelector{}).Error)
	require.NoError(b, db.Where("1 = 1").Delete(&AttestedNode{}).Error)

	now := time.Now()
	const batch = 1000
	for start := 0; start < n; start += batch {
		nodes := make([]AttestedNode, 0, batch)
		selectors := make([]NodeSelector, 0, 4*batch)
		for i := start; i < min(start+batch, n); i++ {
			id := benchNodeID(i)
			expires := now.AddDate(10, 0, 0)
			if i%2 == 0 {
				expires = now.Add(-time.Hour)
			}
			serial := "serial"
			if i%20 == 0 {
				serial = ""
			}
			nodes = append(nodes, AttestedNode{
				SpiffeID:     id,
				DataType:     fmt.Sprintf("t%d", i%2),
				SerialNumber: serial,
				ExpiresAt:    expires,
				CanReattest:  i%2 == 0,
			})
			selectors = append(selectors,
				NodeSelector{SpiffeID: id, Type: "common", Value: "x"},
				NodeSelector{SpiffeID: id, Type: "g10", Value: strconv.Itoa(i % 10)},
				NodeSelector{SpiffeID: id, Type: "g100", Value: strconv.Itoa(i % 100)},
				NodeSelector{SpiffeID: id, Type: "region", Value: strconv.Itoa(i % 3)},
			)
		}
		require.NoError(b, db.CreateInBatches(nodes, batch).Error)
		require.NoError(b, db.CreateInBatches(selectors, batch).Error)
	}
}

func benchNodeID(i int) string {
	return fmt.Sprintf("spiffe://example.org/spire/agent/%08d", i)
}

func clonePage(p *datastore.Pagination) *datastore.Pagination {
	c := *p
	return &c
}

func selectorCount(nodes []*common.AttestedNode) int {
	var count int
	for _, node := range nodes {
		count += len(node.Selectors)
	}
	return count
}
