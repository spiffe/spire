package entrycache

import (
	"context"
	"database/sql"
	"fmt"
	"testing"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/pkg/server/plugin/datastore"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/proto/spire/types"
	"github.com/spiffe/spire/test/fakes/fakedatastore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	td = spiffeid.RequireTrustDomainFromString("domain.test")
)

const (
	mysqlConnString = "spire:test@tcp(localhost:9999)/spire?parseTime=true"
)

func TestCache(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	ds := fakedatastore.New(t)
	ctx := context.Background()

	createRegistrationEntry := func(entry *common.RegistrationEntry) *common.RegistrationEntry {
		resp, err := ds.CreateRegistrationEntry(ctx, &datastore.CreateRegistrationEntryRequest{
			Entry: entry,
		})
		require.NoError(err)
		return resp.Entry
	}

	setNodeSelectors := func(spiffeID string, selectors ...*common.Selector) {
		_, err := ds.SetNodeSelectors(ctx, &datastore.SetNodeSelectorsRequest{
			Selectors: &datastore.NodeSelectors{
				SpiffeId:  spiffeID,
				Selectors: selectors,
			},
		})
		assert.NoError(err)
	}

	rootID := "spiffe://example.org/root"
	oneID := "spiffe://example.org/1"
	twoID := "spiffe://example.org/2"
	threeID := "spiffe://example.org/3"
	fourID := "spiffe://example.org/4"
	fiveID := "spiffe://example.org/5"
	serverID := "spiffe://example.org/spire/server"

	a1 := &common.Selector{Type: "a", Value: "1"}
	b2 := &common.Selector{Type: "b", Value: "2"}

	//
	//        root             4(a1,b2)
	//        /   \           /
	//       1     2         5
	//            /
	//           3
	//
	// node resolvers map from 2 to 4

	oneEntry := createRegistrationEntry(&common.RegistrationEntry{
		ParentId:  rootID,
		SpiffeId:  oneID,
		Selectors: []*common.Selector{{Type: "not", Value: "relevant"}},
	})

	twoEntry := createRegistrationEntry(&common.RegistrationEntry{
		ParentId:  rootID,
		SpiffeId:  twoID,
		Selectors: []*common.Selector{{Type: "not", Value: "relevant"}},
	})

	threeEntry := createRegistrationEntry(&common.RegistrationEntry{
		ParentId:  twoID,
		SpiffeId:  threeID,
		Selectors: []*common.Selector{{Type: "not", Value: "relevant"}},
	})

	fourEntry := createRegistrationEntry(&common.RegistrationEntry{
		ParentId:  serverID,
		SpiffeId:  fourID,
		Selectors: []*common.Selector{a1, b2},
	})

	fiveEntry := createRegistrationEntry(&common.RegistrationEntry{
		ParentId:  fourID,
		SpiffeId:  fiveID,
		Selectors: []*common.Selector{{Type: "not", Value: "relevant"}},
	})

	setNodeSelectors(twoID, a1, b2)

	expected, err := api.RegistrationEntriesToProto([]*common.RegistrationEntry{
		oneEntry,
		twoEntry,
		threeEntry,
		fourEntry,
		fiveEntry,
	})
	require.NoError(err)

	cache, err := Build(context.Background(), makeEntryIteratorDS(ds), makeAgentIteratorDS(ds))
	assert.NoError(err)

	actual := cache.GetAuthorizedEntries(spiffeid.RequireFromString(rootID))

	assert.Equal(expected, actual)
}

func TestFullCacheNodeAliasing(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	ds := fakedatastore.New(t)

	createRegistrationEntry := func(entry *common.RegistrationEntry) *common.RegistrationEntry {
		resp, err := ds.CreateRegistrationEntry(context.Background(), &datastore.CreateRegistrationEntryRequest{
			Entry: entry,
		})
		require.NoError(err)
		return resp.Entry
	}

	setNodeSelectors := func(spiffeID string, selectors ...*common.Selector) {
		_, err := ds.SetNodeSelectors(context.Background(), &datastore.SetNodeSelectorsRequest{
			Selectors: &datastore.NodeSelectors{
				SpiffeId:  spiffeID,
				Selectors: selectors,
			},
		})
		assert.NoError(err)
	}

	agent1ID := spiffeid.RequireFromString("spiffe://example.org/spire/agent/agent1")
	agent2ID := spiffeid.RequireFromString("spiffe://example.org/spire/agent/agent2")
	agent3ID := spiffeid.RequireFromString("spiffe://example.org/spire/agent/agent3")

	s1 := &common.Selector{Type: "s", Value: "1"}
	s2 := &common.Selector{Type: "s", Value: "2"}
	s3 := &common.Selector{Type: "s", Value: "3"}

	alias1 := createRegistrationEntry(&common.RegistrationEntry{
		ParentId:  "spiffe://example.org/spire/server",
		SpiffeId:  "spiffe://example.org/agent1",
		Selectors: []*common.Selector{s1, s2},
	})

	alias2 := createRegistrationEntry(&common.RegistrationEntry{
		ParentId:  "spiffe://example.org/spire/server",
		SpiffeId:  "spiffe://example.org/agent2",
		Selectors: []*common.Selector{s1},
	})

	workload1 := createRegistrationEntry(&common.RegistrationEntry{
		ParentId:  alias1.SpiffeId,
		SpiffeId:  "spiffe://example.org/workload1",
		Selectors: []*common.Selector{{Type: "not", Value: "relevant"}},
	})

	workload2 := createRegistrationEntry(&common.RegistrationEntry{
		ParentId:  alias2.SpiffeId,
		SpiffeId:  "spiffe://example.org/workload2",
		Selectors: []*common.Selector{{Type: "not", Value: "relevant"}},
	})

	workload3 := createRegistrationEntry(&common.RegistrationEntry{
		ParentId:  agent3ID.String(),
		SpiffeId:  "spiffe://example.org/workload3",
		Selectors: []*common.Selector{{Type: "not", Value: "relevant"}},
	})

	setNodeSelectors(agent1ID.String(), s1, s2)
	setNodeSelectors(agent2ID.String(), s1, s3)

	cache, err := Build(context.Background(), makeEntryIteratorDS(ds), makeAgentIteratorDS(ds))
	assert.NoError(err)

	assertAuthorizedEntries := func(agentID spiffeid.ID, entries ...*common.RegistrationEntry) {
		expected, err := api.RegistrationEntriesToProto(entries)
		require.NoError(err)
		assert.Equal(expected, cache.GetAuthorizedEntries(agentID))
	}

	assertAuthorizedEntries(agent1ID, alias1, workload1, alias2, workload2)
	assertAuthorizedEntries(agent2ID, alias2, workload2)
	assertAuthorizedEntries(agent3ID, workload3)
}

//func TestBuildMem(t *testing.T) {
//	staticSelector1 := &types.Selector{
//		Type:  "static",
//		Value: "static-1",
//	}
//	staticSelector2 := &types.Selector{
//		Type:  "static",
//		Value: "static-1",
//	}
//
//	aliasID1 := &types.SPIFFEID{
//		TrustDomain: "domain.test",
//		Path:        "/alias1",
//	}
//
//	aliasID2 := &types.SPIFFEID{
//		TrustDomain: "domain.test",
//		Path:        "/alias2",
//	}
//
//	var agents []Agent
//	for i := 0; i < 50000; i++ {
//		agents = append(agents, Agent{
//			ID: makeAgentID(i),
//			Selectors: []*types.Selector{
//				staticSelector1,
//			},
//		})
//	}
//
//	var allEntries = []*types.Entry{
//		// Alias
//		{
//			Id:       "alias1",
//			SpiffeId: aliasID1,
//			ParentId: &types.SPIFFEID{
//				TrustDomain: "domain.test",
//				Path:        "/spire/server",
//			},
//			Selectors: []*types.Selector{
//				staticSelector1,
//			},
//		},
//		// False alias
//		{
//			Id:       "alias2",
//			SpiffeId: aliasID2,
//			ParentId: &types.SPIFFEID{
//				TrustDomain: "domain.test",
//				Path:        "/spire/server",
//			},
//			Selectors: []*types.Selector{
//				staticSelector2,
//			},
//		},
//	}
//
//	var workloadEntries1 []*types.Entry
//	for i := 0; i < 300; i++ {
//		workloadEntries1 = append(workloadEntries1, &types.Entry{
//			Id: fmt.Sprintf("workload%d", i),
//			SpiffeId: &types.SPIFFEID{
//				TrustDomain: "domain.test",
//				Path:        fmt.Sprintf("workload%d", i),
//			},
//			ParentId: aliasID1,
//			Selectors: []*types.Selector{
//				{Type: "unix", Value: fmt.Sprintf("uid:%d", i)},
//			},
//		})
//	}
//
//	var workloadEntries2 []*types.Entry
//	for i := 0; i < 300; i++ {
//		workloadEntries2 = append(workloadEntries2, &types.Entry{
//			Id: fmt.Sprintf("workload%d", i),
//			SpiffeId: &types.SPIFFEID{
//				TrustDomain: "domain.test",
//				Path:        fmt.Sprintf("workload%d", i),
//			},
//			ParentId: aliasID2,
//			Selectors: []*types.Selector{
//				{Type: "unix", Value: fmt.Sprintf("uid:%d", i)},
//			},
//		})
//	}
//
//	allEntries = append(allEntries, workloadEntries1...)
//	allEntries = append(allEntries, workloadEntries2...)
//
//	PrintMemUsage()
//	_, err := Build(context.Background(), makeEntryIterator(allEntries), makeAgentIterator(agents))
//	if err != nil {
//		t.Fatal(err)
//	}
//	PrintMemUsage()
//
//}
//
//// of garage collection cycles completed.
//func PrintMemUsage() {
//	var m runtime.MemStats
//	runtime.ReadMemStats(&m)
//	// For info on each, see: https://golang.org/pkg/runtime/#MemStats
//	fmt.Printf("Alloc = %v MiB", bToMb(m.Alloc))
//	fmt.Printf("\tTotalAlloc = %v MiB", bToMb(m.TotalAlloc))
//	fmt.Printf("\tSys = %v MiB", bToMb(m.Sys))
//	fmt.Printf("\tNumGC = %v\n", m.NumGC)
//}
//
//func bToMb(b uint64) uint64 {
//	return b / 1024 / 1024
//}
//
//func BenchmarkBuild(b *testing.B) {
//	staticSelector1 := &types.Selector{
//		Type:  "static",
//		Value: "static-1",
//	}
//	staticSelector2 := &types.Selector{
//		Type:  "static",
//		Value: "static-1",
//	}
//
//	aliasID1 := &types.SPIFFEID{
//		TrustDomain: "domain.test",
//		Path:        "/alias1",
//	}
//
//	aliasID2 := &types.SPIFFEID{
//		TrustDomain: "domain.test",
//		Path:        "/alias2",
//	}
//
//	var agents []Agent
//	for i := 0; i < 50000; i++ {
//		agents = append(agents, Agent{
//			ID: makeAgentID(i),
//			Selectors: []*types.Selector{
//				staticSelector1,
//			},
//		})
//	}
//
//	var allEntries = []*types.Entry{
//		// Alias
//		{
//			Id:       "alias1",
//			SpiffeId: aliasID1,
//			ParentId: &types.SPIFFEID{
//				TrustDomain: "domain.test",
//				Path:        "/spire/server",
//			},
//			Selectors: []*types.Selector{
//				staticSelector1,
//			},
//		},
//		// False alias
//		{
//			Id:       "alias2",
//			SpiffeId: aliasID2,
//			ParentId: &types.SPIFFEID{
//				TrustDomain: "domain.test",
//				Path:        "/spire/server",
//			},
//			Selectors: []*types.Selector{
//				staticSelector2,
//			},
//		},
//	}
//
//	var workloadEntries1 []*types.Entry
//	for i := 0; i < 300; i++ {
//		workloadEntries1 = append(workloadEntries1, &types.Entry{
//			Id: fmt.Sprintf("workload%d", i),
//			SpiffeId: &types.SPIFFEID{
//				TrustDomain: "domain.test",
//				Path:        fmt.Sprintf("workload%d", i),
//			},
//			ParentId: aliasID1,
//			Selectors: []*types.Selector{
//				{Type: "unix", Value: fmt.Sprintf("uid:%d", i)},
//			},
//		})
//	}
//
//	var workloadEntries2 []*types.Entry
//	for i := 0; i < 300; i++ {
//		workloadEntries2 = append(workloadEntries2, &types.Entry{
//			Id: fmt.Sprintf("workload%d", i),
//			SpiffeId: &types.SPIFFEID{
//				TrustDomain: "domain.test",
//				Path:        fmt.Sprintf("workload%d", i),
//			},
//			ParentId: aliasID2,
//			Selectors: []*types.Selector{
//				{Type: "unix", Value: fmt.Sprintf("uid:%d", i)},
//			},
//		})
//	}
//
//	allEntries = append(allEntries, workloadEntries1...)
//	allEntries = append(allEntries, workloadEntries2...)
//
//	//for i := 0; i < b.N; i++ {
//	cache, err := Build(context.Background(), makeEntryIterator(allEntries), makeAgentIterator(agents))
//	cache = cache
//	if err != nil {
//		b.Fatal(err)
//	}
//	//}
//
//	b.ResetTimer()
//	for i := 0; i < b.N; i++ {
//		actual := cache.GetAuthorizedEntries(agents[i%len(agents)].ID)
//		actual = actual
//		//require.Equal(b, workloadEntries, actual)
//	}
//}
//
//func XBenchmarkBuildOnMySQL(b *testing.B) {
//	staticSelector1 := &types.Selector{
//		Type:  "static",
//		Value: "static-1",
//	}
//	staticSelector2 := &types.Selector{
//		Type:  "static",
//		Value: "static-1",
//	}
//
//	aliasID1 := &types.SPIFFEID{
//		TrustDomain: "domain.test",
//		Path:        "/alias1",
//	}
//
//	aliasID2 := &types.SPIFFEID{
//		TrustDomain: "domain.test",
//		Path:        "/alias2",
//	}
//
//	var agents []Agent
//	for i := 0; i < 50000; i++ {
//		agents = append(agents, Agent{
//			ID: makeAgentID(i),
//			Selectors: []*types.Selector{
//				staticSelector1,
//			},
//		})
//	}
//
//	var allEntries = []*types.Entry{
//		// Alias
//		{
//			Id:       "alias1",
//			SpiffeId: aliasID1,
//			ParentId: &types.SPIFFEID{
//				TrustDomain: "domain.test",
//				Path:        "/spire/server",
//			},
//			Selectors: []*types.Selector{
//				staticSelector1,
//			},
//		},
//		// False alias
//		{
//			Id:       "alias2",
//			SpiffeId: aliasID2,
//			ParentId: &types.SPIFFEID{
//				TrustDomain: "domain.test",
//				Path:        "/spire/server",
//			},
//			Selectors: []*types.Selector{
//				staticSelector2,
//			},
//		},
//	}
//
//	var workloadEntries1 []*types.Entry
//	for i := 0; i < 300; i++ {
//		workloadEntries1 = append(workloadEntries1, &types.Entry{
//			Id: fmt.Sprintf("workload%d", i),
//			SpiffeId: &types.SPIFFEID{
//				TrustDomain: "domain.test",
//				Path:        fmt.Sprintf("workload%d", i),
//			},
//			ParentId: aliasID1,
//			Selectors: []*types.Selector{
//				{Type: "unix", Value: fmt.Sprintf("uid:%d", i)},
//			},
//		})
//	}
//
//	var workloadEntries2 []*types.Entry
//	for i := 0; i < 300; i++ {
//		workloadEntries2 = append(workloadEntries2, &types.Entry{
//			Id: fmt.Sprintf("workload%d", i),
//			SpiffeId: &types.SPIFFEID{
//				TrustDomain: "domain.test",
//				Path:        fmt.Sprintf("workload%d", i),
//			},
//			ParentId: aliasID2,
//			Selectors: []*types.Selector{
//				{Type: "unix", Value: fmt.Sprintf("uid:%d", i)},
//			},
//		})
//	}
//
//	allEntries = append(allEntries, workloadEntries1...)
//	allEntries = append(allEntries, workloadEntries2...)
//
//	//wipeMySQL(b, mysqlConnString)
//
//	ds := sqlDS.New()
//	ds.SetLogger(hclog.New(nil))
//	_, err := ds.Configure(context.Background(), &spi.ConfigureRequest{
//		Configuration: fmt.Sprintf(`
//	database_type = "mysql"
//	connection_string = %q`, mysqlConnString),
//	})
//	require.NoError(b, err)
//
//	//	fmt.Println("CREATING ENTRIES")
//	//	for i, entry := range allEntries {
//	//		e, _ := api.ProtoToRegistrationEntry(td, entry)
//	//		_, err = ds.CreateRegistrationEntry(context.Background(), &datastore.CreateRegistrationEntryRequest{
//	//			Entry: e,
//	//		})
//	//		if i%100 == 0 {
//	//			fmt.Print(".")
//	//		}
//	//		require.NoError(b, err)
//	//	}
//	//
//	//	fmt.Println("CREATING AGENTS")
//	//	for i, agent := range agents {
//	//		ss, _ := api.SelectorsFromProto(agent.Selectors)
//	//		_, err = ds.SetNodeSelectors(context.Background(), &datastore.SetNodeSelectorsRequest{
//	//			Selectors: &datastore.NodeSelectors{
//	//				SpiffeId:  agent.ID.String(),
//	//				Selectors: ss,
//	//			},
//	//		})
//	//		if i%100 == 0 {
//	//			fmt.Print(".")
//	//		}
//	//		require.NoError(b, err)
//	//	}
//
//	b.ResetTimer()
//	for i := 0; i < b.N; i++ {
//		cache, err := Build(context.Background(), makeEntryIteratorDS(ds), makeAgentIteratorDS(ds))
//		cache = cache
//		if err != nil {
//			b.Fatal(err)
//		}
//	}
//
//	//	b.ResetTimer()
//	//	for i := 0; i < b.N; i++ {
//	//		actual := cache.GetAuthorizedEntries(agents[i%len(agents)].ID)
//	//		actual = actual
//	//		//require.Equal(b, workloadEntries, actual)
//	//	}
//}
//
func makeAgentID(i int) spiffeid.ID {
	return spiffeid.RequireFromString(fmt.Sprintf("spiffe://domain.test/spire/agent/%04d", i))
}

type entryIterator struct {
	entries []*types.Entry
	next    int
}

func makeEntryIterator(entries []*types.Entry) *entryIterator {
	return &entryIterator{
		entries: entries,
	}
}

func (it *entryIterator) Next(ctx context.Context) bool {
	if it.next >= len(it.entries) {
		return false
	}
	it.next++
	return true
}

func (it *entryIterator) Entry() *types.Entry {
	return it.entries[it.next-1]
}

func (it *entryIterator) Err() error {
	return nil
}

type agentIterator struct {
	agents []Agent
	next   int
}

func makeAgentIterator(agents []Agent) *agentIterator {
	return &agentIterator{
		agents: agents,
	}
}

func (it *agentIterator) Next(ctx context.Context) bool {
	if it.next >= len(it.agents) {
		return false
	}
	it.next++
	return true
}

func (it *agentIterator) Agent() Agent {
	return it.agents[it.next-1]
}

func (it *agentIterator) Err() error {
	return nil
}

func __wipePostgres(tb testing.TB, connString string) {
	db, err := sql.Open("postgres", connString)
	require.NoError(tb, err)
	defer db.Close()

	rows, err := db.Query(`SELECT tablename FROM pg_tables WHERE schemaname = 'public';`)
	require.NoError(tb, err)
	defer rows.Close()

	dropTablesInRows(tb, db, rows)
}

func __wipeMySQL(tb testing.TB, connString string) {
	db, err := sql.Open("mysql", connString)
	require.NoError(tb, err)
	defer db.Close()

	rows, err := db.Query(`SELECT table_name FROM information_schema.tables WHERE table_schema = 'spire';`)
	require.NoError(tb, err)
	defer rows.Close()

	dropTablesInRows(tb, db, rows)
}

func dropTablesInRows(tb testing.TB, db *sql.DB, rows *sql.Rows) {
	for rows.Next() {
		var q string
		err := rows.Scan(&q)
		require.NoError(tb, err)
		_, err = db.Exec("DROP TABLE IF EXISTS " + q + " CASCADE")
		require.NoError(tb, err)
	}
	require.NoError(tb, rows.Err())
}
