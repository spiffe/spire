package sqlstorev2

import (
	"cmp"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/pkg/server/datastore/sqlcommon"
	v1 "github.com/spiffe/spire/pkg/server/datastore/sqlstore"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

var entryBenchVerified bool

// BenchmarkRegistrationEntries compares v1's hand-written entry queries with
// v2's on one seeded database. It uses SQLite unless BENCH_DB_TYPE and
// BENCH_DB_CONN are set; BENCH_ENTRIES sets the entry count (default 10000).
func BenchmarkRegistrationEntries(b *testing.B) {
	ctx := context.Background()
	n, err := strconv.Atoi(cmp.Or(os.Getenv("BENCH_ENTRIES"), "10000"))
	require.NoError(b, err)

	dbType := cmp.Or(os.Getenv("BENCH_DB_TYPE"), "sqlite3")
	conn := os.Getenv("BENCH_DB_CONN")
	if dbType == "sqlite3" && conn == "" {
		conn = filepath.ToSlash(filepath.Join(b.TempDir(), "bench.sqlite3"))
	}
	hcl := fmt.Sprintf("database_type = %q\nconnection_string = %q\n", dbType, conn)

	log, _ := test.NewNullLogger()
	log.SetLevel(logrus.ErrorLevel)
	dsV1 := v1.New(log)
	require.NoError(b, dsV1.Configure(ctx, hcl))
	b.Cleanup(func() { dsV1.Close() })

	dsV2 := New(log)
	require.NoError(b, dsV2.Configure(ctx, hcl))
	b.Cleanup(func() { dsV2.Close() })
	seedBenchEntries(b, dsV2, n)
	analyzeBenchTables(b, dsV2)

	sel := func(t, v string) *common.Selector { return &common.Selector{Type: t, Value: v} }
	page := func() *datastore.Pagination { return &datastore.Pagination{PageSize: 1000} }
	yes := true
	entryIDs := make([]string, 0, 100)
	for i := range 100 {
		entryIDs = append(entryIDs, benchEntryID(i*(n/100)))
	}

	lists := []struct {
		name string
		req  func() *datastore.ListRegistrationEntriesRequest
	}{
		{"page", func() *datastore.ListRegistrationEntriesRequest {
			return &datastore.ListRegistrationEntriesRequest{Pagination: page()}
		}},
		{"all", func() *datastore.ListRegistrationEntriesRequest {
			return &datastore.ListRegistrationEntriesRequest{}
		}},
		{"by_parent", func() *datastore.ListRegistrationEntriesRequest {
			return &datastore.ListRegistrationEntriesRequest{ByParentID: benchParentID(7)}
		}},
		{"by_spiffe_id", func() *datastore.ListRegistrationEntriesRequest {
			return &datastore.ListRegistrationEntriesRequest{BySpiffeID: benchSpiffeID(n / 2)}
		}},
		{"by_hint_page", func() *datastore.ListRegistrationEntriesRequest {
			return &datastore.ListRegistrationEntriesRequest{ByHint: "h3", Pagination: page()}
		}},
		{"downstream", func() *datastore.ListRegistrationEntriesRequest {
			return &datastore.ListRegistrationEntriesRequest{ByDownstream: &yes}
		}},
		{"match_any", func() *datastore.ListRegistrationEntriesRequest {
			return &datastore.ListRegistrationEntriesRequest{Pagination: page(), BySelectors: &datastore.BySelectors{
				Match: datastore.MatchAny, Selectors: []*common.Selector{sel("k8s", "sa:1"), sel("k8s", "sa:2")},
			}}
		}},
		{"superset", func() *datastore.ListRegistrationEntriesRequest {
			return &datastore.ListRegistrationEntriesRequest{Pagination: page(), BySelectors: &datastore.BySelectors{
				Match: datastore.Superset, Selectors: []*common.Selector{sel("k8s", "ns:1"), sel("k8s", "sa:1")},
			}}
		}},
		{"subset", func() *datastore.ListRegistrationEntriesRequest {
			// What the agent API asks for a workload: its selectors.
			return &datastore.ListRegistrationEntriesRequest{Pagination: page(), BySelectors: &datastore.BySelectors{
				Match: datastore.Subset, Selectors: []*common.Selector{sel("k8s", "ns:1"), sel("k8s", "sa:1"), sel("k8s", "sa:11"), sel("unix", "uid:1"), sel("unix", "uid:101")},
			}}
		}},
		{"exact", func() *datastore.ListRegistrationEntriesRequest {
			return &datastore.ListRegistrationEntriesRequest{Pagination: page(), BySelectors: &datastore.BySelectors{
				Match: datastore.Exact, Selectors: []*common.Selector{sel("k8s", "ns:1"), sel("k8s", "sa:1"), sel("unix", "uid:1")},
			}}
		}},
		{"federates_any", func() *datastore.ListRegistrationEntriesRequest {
			return &datastore.ListRegistrationEntriesRequest{Pagination: page(), ByFederatesWith: &datastore.ByFederatesWith{
				Match: datastore.MatchAny, TrustDomains: []string{"spiffe://td1.org"},
			}}
		}},
		{"federates_exact", func() *datastore.ListRegistrationEntriesRequest {
			return &datastore.ListRegistrationEntriesRequest{Pagination: page(), ByFederatesWith: &datastore.ByFederatesWith{
				Match: datastore.Exact, TrustDomains: []string{"spiffe://td1.org", "spiffe://td2.org"},
			}}
		}},
		{"federates_subset", func() *datastore.ListRegistrationEntriesRequest {
			return &datastore.ListRegistrationEntriesRequest{Pagination: page(), ByFederatesWith: &datastore.ByFederatesWith{
				Match: datastore.Subset, TrustDomains: []string{"spiffe://td1.org", "spiffe://td2.org"},
			}}
		}},
	}

	impls := []struct {
		name string
		ds   datastore.DataStore
	}{{"v1", dsV1}, {"v2", dsV2}}

	verify := !entryBenchVerified && os.Getenv("BENCH_VERIFY") != "0"
	entryBenchVerified = true

	for _, l := range lists {
		if verify {
			r1, err := listAllEntries(ctx, dsV1, l.req())
			require.NoError(b, err)
			r2, err := listAllEntries(ctx, dsV2, l.req())
			require.NoError(b, err)
			requireSameEntries(b, r1, r2, l.name)
		}
		for _, impl := range impls {
			b.Run("case="+l.name+"/impl="+impl.name, func(b *testing.B) {
				for b.Loop() {
					if _, err := listAllEntries(ctx, impl.ds, l.req()); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}

	counts := []struct {
		name string
		req  *datastore.CountRegistrationEntriesRequest
	}{
		{"count_all", &datastore.CountRegistrationEntriesRequest{}},
		{"count_parent", &datastore.CountRegistrationEntriesRequest{ByParentID: benchParentID(7)}},
		{"count_superset", &datastore.CountRegistrationEntriesRequest{BySelectors: &datastore.BySelectors{
			Match: datastore.Superset, Selectors: []*common.Selector{sel("k8s", "ns:1")},
		}}},
	}
	for _, c := range counts {
		if verify {
			c1, err := dsV1.CountRegistrationEntries(ctx, c.req)
			require.NoError(b, err)
			c2, err := dsV2.CountRegistrationEntries(ctx, c.req)
			require.NoError(b, err)
			require.Equal(b, c1, c2, c.name)
		}
		for _, impl := range impls {
			b.Run("case="+c.name+"/impl="+impl.name, func(b *testing.B) {
				for b.Loop() {
					if _, err := impl.ds.CountRegistrationEntries(ctx, c.req); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}

	existing, err := dsV2.FetchRegistrationEntries(ctx, []string{benchEntryID(n / 3)})
	require.NoError(b, err)
	similar := proto.Clone(existing[benchEntryID(n/3)]).(*common.RegistrationEntry)
	similar.EntryId = ""

	if verify {
		f1, err := dsV1.FetchRegistrationEntries(ctx, entryIDs)
		require.NoError(b, err)
		f2, err := dsV2.FetchRegistrationEntries(ctx, entryIDs)
		require.NoError(b, err)
		require.Len(b, f2, len(entryIDs))
		for id, e := range f1 {
			requireSameEntries(b, []*common.RegistrationEntry{e}, []*common.RegistrationEntry{f2[id]}, "fetch")
		}
	}
	for _, impl := range impls {
		b.Run("case=fetch_100/impl="+impl.name, func(b *testing.B) {
			for b.Loop() {
				if _, err := impl.ds.FetchRegistrationEntries(ctx, entryIDs); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run("case=fetch_1/impl="+impl.name, func(b *testing.B) {
			for b.Loop() {
				if _, err := impl.ds.FetchRegistrationEntries(ctx, entryIDs[:1]); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run("case=create_delete/impl="+impl.name, func(b *testing.B) {
			for b.Loop() {
				e := proto.Clone(similar).(*common.RegistrationEntry)
				e.SpiffeId += "/new"
				created, err := impl.ds.CreateRegistrationEntry(ctx, e)
				if err != nil {
					b.Fatal(err)
				}
				if _, err := impl.ds.DeleteRegistrationEntry(ctx, created.EntryId); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run("case=update/impl="+impl.name, func(b *testing.B) {
			for b.Loop() {
				if _, err := impl.ds.UpdateRegistrationEntry(ctx, existing[benchEntryID(n/3)], nil); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run("case=create_existing/impl="+impl.name, func(b *testing.B) {
			for b.Loop() {
				if _, found, err := impl.ds.CreateOrReturnRegistrationEntry(ctx, similar); err != nil || !found {
					b.Fatal(err, found)
				}
			}
		})
	}
}

func listAllEntries(ctx context.Context, ds datastore.DataStore, req *datastore.ListRegistrationEntriesRequest) ([]*common.RegistrationEntry, error) {
	var all []*common.RegistrationEntry
	for {
		resp, err := ds.ListRegistrationEntries(ctx, req)
		if err != nil {
			return nil, err
		}
		all = append(all, resp.Entries...)
		if resp.Pagination == nil || resp.Pagination.Token == "" {
			return all, nil
		}
		req.Pagination = resp.Pagination
	}
}

func requireSameEntries(t testing.TB, want, got []*common.RegistrationEntry, msg string) {
	t.Helper()
	norm := func(in []*common.RegistrationEntry) []*common.RegistrationEntry {
		out := make([]*common.RegistrationEntry, 0, len(in))
		for _, e := range in {
			c := proto.Clone(e).(*common.RegistrationEntry)
			slices.Sort(c.FederatesWith)
			out = append(out, c)
		}
		return out
	}
	w, g := norm(want), norm(got)
	require.Len(t, g, len(w), msg)
	for i := range w {
		require.True(t, proto.Equal(w[i], g[i]), "%s: entry %d differs:\nv1 %v\nv2 %v", msg, i, w[i], g[i])
	}
}

// seedBenchEntries fills the entry tables with n entries over n/100 parents,
// each with 3 selectors and some with DNS names, trust domains, hints and
// downstream set; a database already holding n entries is reused.
func seedBenchEntries(b *testing.B, ds *Plugin, n int) {
	db := ds.db.DB
	var have int64
	require.NoError(b, db.Model(&RegisteredEntry{}).Count(&have).Error)
	if have == int64(n) {
		return
	}
	for _, m := range []any{&FederatedRegistrationEntry{}, &Selector{}, &DNSName{}, &RegisteredEntry{}, &Bundle{}} {
		require.NoError(b, db.Where("1 = 1").Delete(m).Error)
	}

	bundles := make([]Bundle, 5)
	for i := range bundles {
		bundles[i] = Bundle{ID: uint(i + 1), TrustDomain: fmt.Sprintf("spiffe://td%d.org", i), Data: []byte("x")}
	}
	require.NoError(b, db.Create(&bundles).Error)

	const batch = 1000
	for start := 0; start < n; start += batch {
		var (
			entries   []RegisteredEntry
			selectors []Selector
			dnsNames  []DNSName
			federated []FederatedRegistrationEntry
		)
		for i := start; i < min(start+batch, n); i++ {
			id := uint(i + 1)
			e := RegisteredEntry{
				ID:         id,
				EntryID:    benchEntryID(i),
				SpiffeID:   benchSpiffeID(i),
				ParentID:   benchParentID(i % max(1, n/100)),
				TTL:        3600,
				Downstream: i%100 == 0,
			}
			if i%10 == 0 {
				e.Hint = fmt.Sprintf("h%d", i%7)
			}
			entries = append(entries, e)
			selectors = append(selectors,
				Selector{RegisteredEntryID: id, Type: "k8s", Value: fmt.Sprintf("ns:%d", i%50)},
				Selector{RegisteredEntryID: id, Type: "k8s", Value: fmt.Sprintf("sa:%d", i%500)},
				Selector{RegisteredEntryID: id, Type: "unix", Value: fmt.Sprintf("uid:%d", i%1000)},
			)
			if i%4 == 0 {
				dnsNames = append(dnsNames, DNSName{RegisteredEntryID: id, Value: fmt.Sprintf("e%d.example.org", i)})
			}
			if i%3 == 0 {
				federated = append(federated, FederatedRegistrationEntry{BundleID: uint(i%5 + 1), RegisteredEntryID: id})
				if i%2 == 0 {
					federated = append(federated, FederatedRegistrationEntry{BundleID: uint((i+1)%5 + 1), RegisteredEntryID: id})
				}
			}
		}
		require.NoError(b, db.Omit("wit_svid_ttl").CreateInBatches(entries, batch).Error)
		require.NoError(b, db.CreateInBatches(selectors, batch).Error)
		if len(dnsNames) > 0 {
			require.NoError(b, db.CreateInBatches(dnsNames, batch).Error)
		}
		if len(federated) > 0 {
			require.NoError(b, db.CreateInBatches(federated, batch).Error)
		}
	}
}

func benchEntryID(i int) string  { return fmt.Sprintf("entry-%08d", i) }
func benchSpiffeID(i int) string { return fmt.Sprintf("spiffe://example.org/workload/%08d", i) }
func benchParentID(i int) string { return fmt.Sprintf("spiffe://example.org/spire/agent/%06d", i) }

// analyzeBenchTables fixes the id sequences and refreshes the planner statistics a freshly seeded
// database lacks until autovacuum (PostgreSQL) or the next automatic
// recalculation (MySQL) runs, so plans match a live deployment.
func analyzeBenchTables(b *testing.B, ds *Plugin) {
	switch {
	case sqlcommon.IsPostgresDbType(ds.DatabaseType()):
		// The seed sets ids explicitly, which PostgreSQL sequences do not follow.
		for _, table := range []string{"registered_entries", "bundles"} {
			require.NoError(b, ds.db.Exec(fmt.Sprintf("SELECT setval(pg_get_serial_sequence('%[1]s', 'id'), (SELECT MAX(id) FROM %[1]s))", table)).Error)
		}
		require.NoError(b, ds.db.Exec("ANALYZE").Error)
	case sqlcommon.IsMySQLDbType(ds.DatabaseType()):
		require.NoError(b, ds.db.Exec("ANALYZE TABLE registered_entries, selectors, dns_names, federated_registration_entries, bundles").Error)
	}
}
