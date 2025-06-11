package entrycache

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"sort"
	"strconv"
	"testing"
	"time"

	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/common/protoutil"
	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/pkg/server/datastore"
	sqlds "github.com/spiffe/spire/pkg/server/datastore/sqlstore"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/fakes/fakedatastore"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	spiffeScheme     = "spiffe"
	trustDomain      = "example.org"
	testNodeAttestor = "test-nodeattestor"
	serverID         = "spiffe://example.org/spire/server"
)

var (
	_  EntryIterator = (*entryIterator)(nil)
	_  AgentIterator = (*agentIterator)(nil)
	_  EntryIterator = (*errorEntryIterator)(nil)
	_  AgentIterator = (*errorAgentIterator)(nil)
	td               = spiffeid.RequireTrustDomainFromString("domain.test")
	// The following are set by the linker during integration tests to
	// run these unit tests against various SQL backends.
	TestDialect      string
	TestConnString   string
	TestROConnString string
)

func TestCache(t *testing.T) {
	ds := fakedatastore.New(t)
	ctx := context.Background()

	rootID := spiffeid.RequireFromString("spiffe://example.org/root")

	const numEntries = 5
	entryIDs := make([]string, numEntries)
	for i := range numEntries {
		entryIDURI := url.URL{
			Scheme: spiffeScheme,
			Host:   trustDomain,
			Path:   "/" + strconv.Itoa(i),
		}

		entryIDs[i] = entryIDURI.String()
	}

	a1 := &common.Selector{Type: "a", Value: "1"}
	b2 := &common.Selector{Type: "b", Value: "2"}

	irrelevantSelectors := []*common.Selector{
		{Type: "not", Value: "relevant"},
	}

	//
	//        root             3(a1,b2)
	//        /   \           /
	//       0     1         4
	//            /
	//           2
	//
	// node resolvers map from 1 to 3

	entriesToCreate := []*common.RegistrationEntry{
		{
			ParentId:  rootID.String(),
			SpiffeId:  entryIDs[0],
			Selectors: irrelevantSelectors,
		},
		{
			ParentId:  rootID.String(),
			SpiffeId:  entryIDs[1],
			Selectors: irrelevantSelectors,
		},
		{
			ParentId:  entryIDs[1],
			SpiffeId:  entryIDs[2],
			Selectors: irrelevantSelectors,
		},
		{
			ParentId:  serverID,
			SpiffeId:  entryIDs[3],
			Selectors: []*common.Selector{a1, b2},
		},
		{

			ParentId:  entryIDs[3],
			SpiffeId:  entryIDs[4],
			Selectors: irrelevantSelectors,
		},
	}

	entries := make([]*common.RegistrationEntry, len(entriesToCreate))
	for i, e := range entriesToCreate {
		entries[i] = createRegistrationEntry(ctx, t, ds, e)
	}

	node := &common.AttestedNode{
		SpiffeId:            entryIDs[1],
		AttestationDataType: "test-nodeattestor",
		CertSerialNumber:    "node-1",
		CertNotAfter:        time.Now().Add(24 * time.Hour).Unix(),
	}

	createAttestedNode(t, ds, node)
	setNodeSelectors(ctx, t, ds, entryIDs[1], a1, b2)

	cache, err := BuildFromDataStore(context.Background(), "example.org", ds)
	assert.NoError(t, err)

	expected := entries[:3]
	expected = append(expected, entries[4])
	assertAuthorizedEntries(t, cache, rootID, entries, expected...)
}

func TestCacheAfterRenamingTrustDomain(t *testing.T) {
	ds := fakedatastore.New(t)
	ctx := context.Background()

	irrelevantSelectors := []*common.Selector{
		{Type: "not", Value: "relevant"},
	}

	entriesToCreate := []*common.RegistrationEntry{
		{
			ParentId:  "spiffe://example1.org/agent",
			SpiffeId:  "spiffe://example1.org/workload",
			Selectors: irrelevantSelectors,
		},
		{
			ParentId:  "spiffe://example2.org/agent",
			SpiffeId:  "spiffe://example1.org/anotherworkload",
			Selectors: irrelevantSelectors,
		},
		// Only this entry should be returned as authorized by the agent
		{
			ParentId:  "spiffe://example2.org/agent",
			SpiffeId:  "spiffe://example2.org/workload",
			Selectors: irrelevantSelectors,
		},
	}

	entries := make([]*common.RegistrationEntry, len(entriesToCreate))
	for i, e := range entriesToCreate {
		entries[i] = createRegistrationEntry(ctx, t, ds, e)
	}

	node := &common.AttestedNode{
		SpiffeId:            "spiffe://example2.org/agent",
		AttestationDataType: "test-nodeattestor",
		CertSerialNumber:    "node-1",
		CertNotAfter:        time.Now().Add(24 * time.Hour).Unix(),
	}

	createAttestedNode(t, ds, node)
	a1 := &common.Selector{Type: "a", Value: "1"}
	b2 := &common.Selector{Type: "b", Value: "2"}
	setNodeSelectors(ctx, t, ds, "spiffe://example2.org/agent", a1, b2)

	cache, err := BuildFromDataStore(context.Background(), "example2.org", ds)
	assert.NoError(t, err)

	expected := entries[2:3]
	assertAuthorizedEntries(t, cache, spiffeid.RequireFromString("spiffe://example2.org/agent"), entries, expected...)
}

func TestFullCacheNodeAliasing(t *testing.T) {
	ds := fakedatastore.New(t)
	ctx := context.Background()

	const serverID = "spiffe://example.org/spire/server"
	agentIDs := []spiffeid.ID{
		spiffeid.RequireFromString("spiffe://example.org/spire/agent/agent1"),
		spiffeid.RequireFromString("spiffe://example.org/spire/agent/agent2"),
		spiffeid.RequireFromString("spiffe://example.org/spire/agent/agent3"),
	}

	s1 := &common.Selector{Type: "s", Value: "1"}
	s2 := &common.Selector{Type: "s", Value: "2"}
	s3 := &common.Selector{Type: "s", Value: "3"}

	irrelevantSelectors := []*common.Selector{
		{Type: "not", Value: "relevant"},
	}

	nodeAliasEntriesToCreate := []*common.RegistrationEntry{
		{
			ParentId:  serverID,
			SpiffeId:  "spiffe://example.org/agent1",
			Selectors: []*common.Selector{s1, s2},
		},
		{
			ParentId:  serverID,
			SpiffeId:  "spiffe://example.org/agent2",
			Selectors: []*common.Selector{s1},
		},
	}

	nodeAliasEntries := make([]*common.RegistrationEntry, len(nodeAliasEntriesToCreate))
	for i, e := range nodeAliasEntriesToCreate {
		nodeAliasEntries[i] = createRegistrationEntry(ctx, t, ds, e)
	}

	workloadEntriesToCreate := []*common.RegistrationEntry{
		{
			ParentId:  nodeAliasEntries[0].SpiffeId,
			SpiffeId:  "spiffe://example.org/workload1",
			Selectors: irrelevantSelectors,
		},
		{
			ParentId:  nodeAliasEntries[1].SpiffeId,
			SpiffeId:  "spiffe://example.org/workload2",
			Selectors: irrelevantSelectors,
		},
		{
			ParentId:  agentIDs[2].String(),
			SpiffeId:  "spiffe://example.org/workload3",
			Selectors: irrelevantSelectors,
		},
	}

	workloadEntries := make([]*common.RegistrationEntry, len(workloadEntriesToCreate))
	for i, e := range workloadEntriesToCreate {
		workloadEntries[i] = createRegistrationEntry(ctx, t, ds, e)
	}

	for i, agentID := range agentIDs {
		node := &common.AttestedNode{
			SpiffeId:            agentID.String(),
			AttestationDataType: testNodeAttestor,
			CertSerialNumber:    strconv.Itoa(i),
			CertNotAfter:        time.Now().Add(24 * time.Hour).Unix(),
		}

		createAttestedNode(t, ds, node)
	}

	setNodeSelectors(ctx, t, ds, agentIDs[0].String(), s1, s2)
	setNodeSelectors(ctx, t, ds, agentIDs[1].String(), s1, s3)

	cache, err := BuildFromDataStore(context.Background(), "example.org", ds)
	assert.NoError(t, err)

	assertAuthorizedEntries(t, cache, agentIDs[0], workloadEntries, workloadEntries[:2]...)
	assertAuthorizedEntries(t, cache, agentIDs[1], workloadEntries, workloadEntries[1])
	assertAuthorizedEntries(t, cache, agentIDs[2], workloadEntries, workloadEntries[2])
}

func TestFullCacheExcludesNodeSelectorMappedEntriesForExpiredAgents(t *testing.T) {
	// This test verifies that the cache contains no workloads parented to alias entries
	// that are only associated with an expired agent.
	//
	// Data used in this test:
	//
	// Registration entry graph:
	// (agent SPIFFE IDs are shown as parented to the root for simplicity of illustrating the hierarchy)
	//
	//           ---------------------------root------------------------
	//          /             |              |               |          \
	//   group/0          group/1         group/2      agent/active    agent/expired
	//      |                |              |                |            \
	//  workload/0       workload/1     workload/2      workload/3     workload/4
	//
	// Agents:
	// - agent/active - has a CertNotAfter that is still valid
	// - agent/expired - has a CertNotAfter that expired
	//
	// agent/active maps to group/0 and group/1 based on selector subset matches.
	// agent/expired maps to group/0 and group/2 based on selector subset matches.
	//
	// Normally, agent/expired should be authorized to receive group/0, workload/0, group/2, workload/2, and workload/4.
	// However, the cache filters out all entries related to the expired agent other than ones shared with other Agents
	// through node selector subset matching - in this case, just workload/0.
	// In reality, an expired agent should not be able to request its authorized entries because endpoint security
	// (mTLS on connection establishment and authorization middleware on subsequent requests over the connection)
	// will prevent the RPC from being handled.
	// The main point of this test is to demonstrate that the cache is capable of filtering out data that will never be
	// used by clients in order to minimize the memory footprint.
	// This is a mitigation for performance problems that arise when hydrating the cache today
	// due to stale expired Agent data remaining in the datastore: https://github.com/spiffe/spire/issues/1836

	ds := fakedatastore.New(t)
	ctx := context.Background()
	serverURI := &url.URL{
		Scheme: spiffeScheme,
		Host:   trustDomain,
		Path:   "/spire/server",
	}

	serverID := spiffeid.RequireFromURI(serverURI)
	buildAgentID := func(agentName string) spiffeid.ID {
		agentURI := &url.URL{
			Scheme: spiffeScheme,
			Host:   trustDomain,
			Path:   fmt.Sprintf("/spire/agent/%s", agentName),
		}

		return spiffeid.RequireFromURI(agentURI)
	}

	expiredAgentID := buildAgentID("expired-1")
	expiredAgentIDStr := expiredAgentID.String()
	expiredAgent := &common.AttestedNode{
		SpiffeId:            expiredAgentIDStr,
		AttestationDataType: testNodeAttestor,
		CertSerialNumber:    "expired-agent",
		CertNotAfter:        time.Now().Add(-24 * time.Hour).Unix(),
	}

	activeAgentID := buildAgentID("active-1")
	activeAgentIDStr := activeAgentID.String()
	activeAgent := &common.AttestedNode{
		SpiffeId:            activeAgentIDStr,
		AttestationDataType: testNodeAttestor,
		CertSerialNumber:    "active-agent",
		CertNotAfter:        time.Now().Add(24 * time.Hour).Unix(),
	}

	createAttestedNode(t, ds, expiredAgent)
	createAttestedNode(t, ds, activeAgent)

	globalSelectors := []*common.Selector{
		{
			Type:  "static",
			Value: "global",
		},
	}

	const nodeGroupSelectorType = "node-group"
	expiredAgentSelectors := []*common.Selector{
		{
			Type:  nodeGroupSelectorType,
			Value: "group-1",
		},
	}

	expiredAgentSelectors = append(expiredAgentSelectors, globalSelectors...)
	activeAgentSelectors := []*common.Selector{
		{
			Type:  nodeGroupSelectorType,
			Value: "group-2",
		},
	}

	activeAgentSelectors = append(activeAgentSelectors, globalSelectors...)

	setNodeSelectors(ctx, t, ds, expiredAgentIDStr, expiredAgentSelectors...)
	setNodeSelectors(ctx, t, ds, activeAgentIDStr, activeAgentSelectors...)

	const numAliasEntries = 3
	aliasEntryIDs := make([]string, numAliasEntries)
	for i := range numAliasEntries {
		entryURI := &url.URL{
			Scheme: spiffeScheme,
			Host:   trustDomain,
			Path:   fmt.Sprintf("/group/%d", i),
		}

		aliasEntryIDs[i] = spiffeid.RequireFromURI(entryURI).String()
	}

	aliasEntriesToCreate := []*common.RegistrationEntry{
		{
			ParentId:  serverID.String(),
			SpiffeId:  aliasEntryIDs[0],
			Selectors: globalSelectors,
		},
		{
			ParentId:  serverID.String(),
			SpiffeId:  aliasEntryIDs[1],
			Selectors: activeAgentSelectors,
		},
		{
			ParentId:  serverID.String(),
			SpiffeId:  aliasEntryIDs[2],
			Selectors: expiredAgentSelectors,
		},
	}

	aliasEntries := make([]*common.RegistrationEntry, numAliasEntries)
	for i := range numAliasEntries {
		aliasEntries[i] = createRegistrationEntry(ctx, t, ds, aliasEntriesToCreate[i])
	}

	const numWorkloadEntries = 5
	workloadEntryIDs := make([]string, numWorkloadEntries)
	for i := range numWorkloadEntries {
		entryURI := &url.URL{
			Scheme: spiffeScheme,
			Host:   trustDomain,
			Path:   fmt.Sprintf("/workload/%d", i),
		}

		workloadEntryIDs[i] = spiffeid.RequireFromURI(entryURI).String()
	}

	irrelevantSelectors := []*common.Selector{
		{
			Type:  "doesn't",
			Value: "matter",
		},
	}

	workloadEntriesToCreate := []*common.RegistrationEntry{
		{
			ParentId:  aliasEntries[0].SpiffeId,
			SpiffeId:  workloadEntryIDs[0],
			Selectors: irrelevantSelectors,
		},
		{
			ParentId:  aliasEntries[1].SpiffeId,
			SpiffeId:  workloadEntryIDs[1],
			Selectors: irrelevantSelectors,
		},
		{
			ParentId:  aliasEntries[2].SpiffeId,
			SpiffeId:  workloadEntryIDs[2],
			Selectors: irrelevantSelectors,
		},
		{
			ParentId:  activeAgentIDStr,
			SpiffeId:  workloadEntryIDs[3],
			Selectors: irrelevantSelectors,
		},
		{
			ParentId:  expiredAgentIDStr,
			SpiffeId:  workloadEntryIDs[4],
			Selectors: irrelevantSelectors,
		},
	}

	workloadEntries := make([]*common.RegistrationEntry, numWorkloadEntries)
	for i := range numWorkloadEntries {
		workloadEntries[i] = createRegistrationEntry(ctx, t, ds, workloadEntriesToCreate[i])
	}

	c, err := BuildFromDataStore(ctx, "example.org", ds)
	require.NoError(t, err)
	require.NotNil(t, c)

	entries := c.GetAuthorizedEntries(expiredAgentID)
	require.Len(t, entries, 1)

	expectedEntry, err := api.RegistrationEntryToProto(workloadEntries[numWorkloadEntries-1])
	require.NoError(t, err)
	spiretest.AssertProtoEqual(t, expectedEntry, entries[0].Clone(protoutil.AllTrueEntryMask))
}

func TestBuildIteratorError(t *testing.T) {
	tests := []struct {
		desc    string
		entryIt EntryIterator
		agentIt AgentIterator
	}{
		{
			desc:    "entry iterator error",
			entryIt: &errorEntryIterator{},
			agentIt: makeAgentIterator(nil),
		},
		{
			desc:    "agent iterator error",
			entryIt: makeEntryIterator(nil),
			agentIt: &errorAgentIterator{},
		},
	}

	ctx := context.Background()
	for _, tt := range tests {
		entryIt := tt.entryIt
		agentIt := tt.agentIt
		t.Run(tt.desc, func(t *testing.T) {
			cache, err := Build(ctx, "example.org", entryIt, agentIt)
			assert.Error(t, err)
			assert.Nil(t, cache)
		})
	}
}

func BenchmarkBuildInMemory(b *testing.B) {
	allEntries, agents := buildBenchmarkData()

	for b.Loop() {
		_, err := Build(context.Background(), "example.org", makeEntryIterator(allEntries), makeAgentIterator(agents))
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkGetAuthorizedEntriesInMemory(b *testing.B) {
	allEntries, agents := buildBenchmarkData()
	cache, err := Build(context.Background(), "example.org", makeEntryIterator(allEntries), makeAgentIterator(agents))
	require.NoError(b, err)
	b.ResetTimer()
	for i := range b.N {
		cache.GetAuthorizedEntries(agents[i%len(agents)].ID)
	}
}

// To run this benchmark against a real MySQL or Postgres database, set the following flags in your test run,
// substituting in the required connection string parameters for each of the ldflags:
// -bench 'BenchmarkBuildSQL' -benchtime <some-reasonable-time-limit> -ldflags "-X github.com/spiffe/spire/pkg/server/cache/entrycache.TestDialect=<mysql|postgres> -X github.com/spiffe/spire/pkg/server/cache/entrycache.TestConnString=<CONNECTION_STRING_HERE> -X github.com/spiffe/spire/pkg/server/cache/entrycache.TestROConnString=<CONNECTION_STRING_HERE>"
func BenchmarkBuildSQL(b *testing.B) {
	allEntries, agents := buildBenchmarkData()
	ctx := context.Background()
	ds := newSQLPlugin(ctx, b)

	for _, entry := range allEntries {
		e, err := api.ProtoToRegistrationEntry(context.Background(), td, entry)
		require.NoError(b, err)
		createRegistrationEntry(ctx, b, ds, e)
	}

	for i, agent := range agents {
		agentIDStr := agent.ID.String()
		node := &common.AttestedNode{
			SpiffeId:            agent.ID.String(),
			AttestationDataType: testNodeAttestor,
			CertSerialNumber:    strconv.Itoa(i),
			CertNotAfter:        time.Now().Add(24 * time.Hour).Unix(),
		}

		createAttestedNode(b, ds, node)
		ss, err := api.SelectorsFromProto(agent.Selectors)
		require.NoError(b, err)
		setNodeSelectors(ctx, b, ds, agentIDStr, ss...)
	}

	for b.Loop() {
		_, err := BuildFromDataStore(ctx, "example.org", ds)
		if err != nil {
			b.Fatal(err)
		}
	}
}

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

func (it *entryIterator) Next(context.Context) bool {
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

func (it *agentIterator) Next(context.Context) bool {
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

type errorEntryIterator struct{}

func (e *errorEntryIterator) Next(context.Context) bool {
	return false
}

func (e *errorEntryIterator) Err() error {
	return errors.New("some entry iterator error")
}

func (e *errorEntryIterator) Entry() *types.Entry {
	return nil
}

type errorAgentIterator struct{}

func (e *errorAgentIterator) Next(context.Context) bool {
	return false
}

func (e *errorAgentIterator) Err() error {
	return errors.New("some agent iterator error")
}

func (e *errorAgentIterator) Agent() Agent {
	return Agent{}
}

func wipePostgres(tb testing.TB, connString string) {
	db, err := sql.Open("postgres", connString)
	require.NoError(tb, err)
	defer db.Close()

	rows, err := db.Query(`SELECT tablename FROM pg_tables WHERE schemaname = 'public';`)
	require.NoError(tb, err)
	defer rows.Close()

	dropTablesInRows(tb, db, rows)
}

func wipeMySQL(tb testing.TB, connString string) {
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

func createRegistrationEntry(ctx context.Context, tb testing.TB, ds datastore.DataStore, entry *common.RegistrationEntry) *common.RegistrationEntry {
	registrationEntry, err := ds.CreateRegistrationEntry(ctx, entry)
	require.NoError(tb, err)
	return registrationEntry
}

func setNodeSelectors(ctx context.Context, tb testing.TB, ds datastore.DataStore, spiffeID string, selectors ...*common.Selector) {
	err := ds.SetNodeSelectors(ctx, spiffeID, selectors)
	require.NoError(tb, err)
}

func buildBenchmarkData() ([]*types.Entry, []Agent) {
	staticSelector1 := &types.Selector{
		Type:  "static",
		Value: "static-1",
	}
	staticSelector2 := &types.Selector{
		Type:  "static",
		Value: "static-1",
	}

	aliasID1 := &types.SPIFFEID{
		TrustDomain: "domain.test",
		Path:        "/alias1",
	}

	aliasID2 := &types.SPIFFEID{
		TrustDomain: "domain.test",
		Path:        "/alias2",
	}

	const numAgents = 50000
	agents := make([]Agent, 0, numAgents)
	for i := range numAgents {
		agents = append(agents, Agent{
			ID: makeAgentID(i),
			Selectors: []*types.Selector{
				staticSelector1,
			},
		})
	}

	var allEntries = []*types.Entry{
		// Alias
		{
			Id:       "alias1",
			SpiffeId: aliasID1,
			ParentId: &types.SPIFFEID{
				TrustDomain: "domain.test",
				Path:        "/spire/server",
			},
			Selectors: []*types.Selector{
				staticSelector1,
			},
		},
		// False alias
		{
			Id:       "alias2",
			SpiffeId: aliasID2,
			ParentId: &types.SPIFFEID{
				TrustDomain: "domain.test",
				Path:        "/spire/server",
			},
			Selectors: []*types.Selector{
				staticSelector2,
			},
		},
	}

	var workloadEntries1 []*types.Entry
	for i := range 300 {
		workloadEntries1 = append(workloadEntries1, &types.Entry{
			Id: fmt.Sprintf("alias1_workload%d", i),
			SpiffeId: &types.SPIFFEID{
				TrustDomain: "domain.test",
				Path:        fmt.Sprintf("/workload%d", i),
			},
			ParentId: aliasID1,
			Selectors: []*types.Selector{
				{Type: "unix", Value: fmt.Sprintf("uid:%d", i)},
			},
		})
	}

	var workloadEntries2 []*types.Entry
	for i := range 300 {
		workloadEntries2 = append(workloadEntries2, &types.Entry{
			Id: fmt.Sprintf("alias2_workload%d", i),
			SpiffeId: &types.SPIFFEID{
				TrustDomain: "domain.test",
				Path:        fmt.Sprintf("/workload%d", i),
			},
			ParentId: aliasID2,
			Selectors: []*types.Selector{
				{Type: "unix", Value: fmt.Sprintf("uid:%d", i)},
			},
		})
	}

	allEntries = append(allEntries, workloadEntries1...)
	allEntries = append(allEntries, workloadEntries2...)
	return allEntries, agents
}

func newSQLPlugin(ctx context.Context, tb testing.TB) datastore.DataStore {
	log, _ := test.NewNullLogger()
	p := sqlds.New(log)

	// When the test suite is executed normally, we test against sqlite3 since
	// it requires no external dependencies. The integration test framework
	// builds the test harness for a specific dialect and connection string
	var cfg string
	switch TestDialect {
	case "":
		dbPath := filepath.Join(spiretest.TempDir(tb), "db.sqlite3")
		cfg = fmt.Sprintf(`
				database_type = "sqlite3"
				log_sql = true
				connection_string = "%s"
				`, dbPath)
	case "mysql":
		require.NotEmpty(tb, TestConnString, "connection string must be set")
		wipeMySQL(tb, TestConnString)
		cfg = fmt.Sprintf(`
				database_type = "mysql"
				log_sql = true
				connection_string = "%s"
				ro_connection_string = "%s"
				`, TestConnString, TestROConnString)
	case "postgres":
		require.NotEmpty(tb, TestConnString, "connection string must be set")
		wipePostgres(tb, TestConnString)
		cfg = fmt.Sprintf(`
				database_type = "postgres"
				log_sql = true
				connection_string = "%s"
				ro_connection_string = "%s"
				`, TestConnString, TestROConnString)
	default:
		require.FailNowf(tb, "Unsupported external test dialect %q", TestDialect)
	}

	err := p.Configure(ctx, cfg)
	require.NoError(tb, err)

	return p
}

func assertAuthorizedEntries(tb testing.TB, cache Cache, agentID spiffeid.ID, allEntries []*common.RegistrationEntry, entries ...*common.RegistrationEntry) {
	tb.Helper()
	expected, err := api.RegistrationEntriesToProto(entries)
	require.NoError(tb, err)

	authorizedEntries := entriesFromReadOnlyEntries(cache.GetAuthorizedEntries(agentID))

	sortEntries(expected)
	sortEntries(authorizedEntries)

	spiretest.AssertProtoListEqual(tb, expected, authorizedEntries)

	assertLookupEntries(tb, cache, agentID, allEntries, entries...)
}

func assertLookupEntries(tb testing.TB, cache Cache, agentID spiffeid.ID, lookup []*common.RegistrationEntry, entries ...*common.RegistrationEntry) {
	tb.Helper()
	expected, err := api.RegistrationEntriesToProto(entries)
	require.NoError(tb, err)
	sortEntries(expected)

	lookupEntries := make(map[string]struct{})
	for _, entry := range lookup {
		lookupEntries[entry.EntryId] = struct{}{}
	}
	foundEntries := cache.LookupAuthorizedEntries(agentID, lookupEntries)
	require.Len(tb, foundEntries, len(entries))
}

func entriesFromReadOnlyEntries(readOnlyEntries []api.ReadOnlyEntry) []*types.Entry {
	entries := []*types.Entry{}
	for _, readOnlyEntry := range readOnlyEntries {
		entries = append(entries, readOnlyEntry.Clone(protoutil.AllTrueEntryMask))
	}
	return entries
}

func sortEntries(es []*types.Entry) {
	sort.Slice(es, func(a, b int) bool {
		return es[a].GetId() < es[b].GetId()
	})
}

func setupLookupTest(tb testing.TB, count int) (*FullEntryCache, []string) {
	ds := fakedatastore.New(tb)
	ctx := context.Background()

	// Create an attested agent
	agentID := spiffeid.RequireFromString("spiffe://example.org/spire/agent/1")
	node := &common.AttestedNode{
		SpiffeId:            agentID.String(),
		AttestationDataType: testNodeAttestor,
		CertSerialNumber:    "1",
		CertNotAfter:        time.Now().Add(24 * time.Hour).Unix(),
	}
	createAttestedNode(tb, ds, node)
	setNodeSelectors(ctx, tb, ds, agentID.String(), &common.Selector{
		Type:  "alias",
		Value: "root",
	})

	// Create root alias
	createRegistrationEntry(ctx, tb, ds, &common.RegistrationEntry{
		ParentId: serverID,
		SpiffeId: "spiffe://example.org/root",
		Selectors: []*common.Selector{
			{
				Type:  "alias",
				Value: "root",
			},
		},
	})

	entries := []string{}
	for id := range count {
		idStr := strconv.Itoa(id)
		// Create one entry parented to the alias
		entry := createRegistrationEntry(ctx, tb, ds, &common.RegistrationEntry{
			ParentId: "spiffe://example.org/root",
			SpiffeId: "spiffe://example.org/workload/" + idStr,
			Selectors: []*common.Selector{
				{
					Type:  "workload",
					Value: "id:" + strconv.Itoa(id),
				},
			},
		})
		entries = append(entries, entry.EntryId)

		// And another one to parented to the workload to verify
		// the lookup recurses.
		entry = createRegistrationEntry(ctx, tb, ds, &common.RegistrationEntry{
			ParentId: "spiffe://example.org/workload/" + idStr,
			SpiffeId: "spiffe://example.org/workload/" + idStr + "/child",
			Selectors: []*common.Selector{
				{
					Type:  "workload",
					Value: "id:" + strconv.Itoa(id),
				},
			},
		})
		entries = append(entries, entry.EntryId)
	}

	cache, err := BuildFromDataStore(ctx, "example.org", ds)
	assert.NoError(tb, err)

	return cache, entries
}

func TestLookupEntries(t *testing.T) {
	agentID := spiffeid.RequireFromString("spiffe://example.org/spire/agent/1")
	cache, entries := setupLookupTest(t, 8)

	found := cache.LookupAuthorizedEntries(agentID, make(map[string]struct{}))
	require.Len(t, found, 0)

	found = cache.LookupAuthorizedEntries(agentID, map[string]struct{}{
		"does-not-exist": {},
	})
	require.Len(t, found, 0)

	found = cache.LookupAuthorizedEntries(agentID, map[string]struct{}{
		"does-not-exist": {},
		entries[1]:       {},
		entries[7]:       {},
		entries[15]:      {},
	})
	require.Contains(t, found, entries[1])
	require.Contains(t, found, entries[7])
	require.Contains(t, found, entries[15])
}

func BenchmarkEntryLookup(b *testing.B) {
	agentID := spiffeid.RequireFromString("spiffe://example.org/spire/agent/1")
	cache, entries := setupLookupTest(b, 256)

	b.ReportAllocs()

	for b.Loop() {
		for _, id := range entries {
			foundEntries := cache.LookupAuthorizedEntries(agentID, map[string]struct{}{
				id: {},
			})
			require.Len(b, foundEntries, 1)
		}
	}
}
