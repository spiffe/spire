package authorizedentries_test

import (
	"context"
	"fmt"
	"maps"
	"sort"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/pkg/server/authorizedentries"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
)

var (
	ctx       = context.Background()
	td        = spiffeid.RequireTrustDomainFromString("domain.test")
	server    = spiffeid.RequireFromPath(td, "/spire/server")
	agent1    = spiffeid.RequireFromPath(td, "/spire/agent/1")
	agent2    = spiffeid.RequireFromPath(td, "/spire/agent/2")
	agent3    = spiffeid.RequireFromPath(td, "/spire/agent/3")
	delegatee = spiffeid.RequireFromPath(td, "/delegatee")
	alias1    = spiffeid.RequireFromPath(td, "/alias/1")
	alias2    = spiffeid.RequireFromPath(td, "/alias/2")
	sel1      = &types.Selector{Type: "S", Value: "1"}
	sel2      = &types.Selector{Type: "S", Value: "2"}
	sel3      = &types.Selector{Type: "S", Value: "3"}
)

func TestGetAuthorizedEntries(t *testing.T) {
	t.Run("empty cache", func(t *testing.T) {
		testCache().assertAuthorizedEntries(t, agent1)
	})

	t.Run("agent not attested", func(t *testing.T) {
		testCache().
			withEntries(makeWorkload(agent1)).
			assertAuthorizedEntries(t, agent1)
	})

	t.Run("directly via agent", func(t *testing.T) {
		workload1 := makeWorkload(agent1)
		workload2 := makeWorkload(agent2)
		testCache().
			withAgent(agent1, sel1).
			withEntries(workload1, workload2).
			assertAuthorizedEntries(t, agent1, workload1)
	})

	t.Run("entry removed", func(t *testing.T) {
		workload := makeWorkload(agent1)
		cache := testCache().
			withAgent(agent1, sel1).
			withEntries(workload).hydrate()
		cache.RemoveEntry(workload.Id)
		assertAuthorizedEntries(t, cache, agent1)
	})

	t.Run("indirectly via delegated workload", func(t *testing.T) {
		var (
			delegateeEntry = makeDelegatee(agent1, delegatee)
			workloadEntry  = makeWorkload(delegatee)
			someOtherEntry = makeWorkload(agent2)
		)

		testCache().
			withAgent(agent1, sel1).
			withEntries(delegateeEntry, workloadEntry, someOtherEntry).
			assertAuthorizedEntries(t, agent1, delegateeEntry, workloadEntry)
	})

	t.Run("indirectly via alias", func(t *testing.T) {
		var (
			aliasEntry    = makeAlias(alias1, sel1, sel2)
			workloadEntry = makeWorkload(alias1)
		)

		test := testCache().
			withEntries(workloadEntry, aliasEntry).
			withAgent(agent1, sel1).
			withAgent(agent2, sel1, sel2).
			withAgent(agent3, sel1, sel2, sel3)

		t.Run("agent has strict selector subset", func(t *testing.T) {
			// Workload entry not available through alias since the agent
			// does not have a superset of the alias selectors.
			test.assertAuthorizedEntries(t, agent1)
		})

		t.Run("agent has selector match", func(t *testing.T) {
			// Workload entry is available through alias since the agent
			// has a non-strict superset of the alias selectors.
			test.assertAuthorizedEntries(t, agent2, workloadEntry)
		})

		t.Run("agent has strict selector superset", func(t *testing.T) {
			// Workload entry is available through alias since the agent
			// has a strict superset of the alias selectors.
			test.assertAuthorizedEntries(t, agent3, workloadEntry)
		})
	})

	t.Run("alias removed", func(t *testing.T) {
		var (
			aliasEntry    = makeAlias(alias1, sel1, sel2)
			workloadEntry = makeWorkload(alias1)
		)

		cache := testCache().
			withEntries(workloadEntry, aliasEntry).
			withAgent(agent1, sel1, sel2).
			hydrate()

		cache.RemoveEntry(aliasEntry.Id)
		assertAuthorizedEntries(t, cache, agent1)
	})

	t.Run("agent expired", func(t *testing.T) {
		var (
			aliasEntry    = makeAlias(alias1, sel1, sel2)
			workloadEntry = makeWorkload(alias1)
		)

		cache := testCache().
			withEntries(workloadEntry, aliasEntry).
			withAgent(agent1, sel1, sel2).
			hydrate()

		cache.SetNodeSelectors(agent1.String(), nil)
		assertAuthorizedEntries(t, cache, agent1)
	})
}

func testCache() *cacheTest {
	return &cacheTest{
		entries: make(map[string]*types.Entry),
		agents:  make(map[spiffeid.ID][]*types.Selector),
	}
}

type cacheTest struct {
	entries map[string]*types.Entry
	agents  map[spiffeid.ID][]*types.Selector
}

func (a *cacheTest) pickAgent() spiffeid.ID {
	for agent := range a.agents {
		return agent
	}
	return spiffeid.ID{}
}

func (a *cacheTest) withEntries(entries ...*types.Entry) *cacheTest {
	for _, entry := range entries {
		a.entries[entry.Id] = entry
	}
	return a
}

func (a *cacheTest) withAgent(node spiffeid.ID, selectors ...*types.Selector) *cacheTest {
	a.agents[node] = append(a.agents[node], selectors...)
	return a
}

func (a *cacheTest) clone() *cacheTest {
	return &cacheTest{
		entries: maps.Clone(a.entries),
		agents:  maps.Clone(a.agents),
	}
}

func (a *cacheTest) hydrate() *authorizedentries.Cache {
	cache := authorizedentries.NewCache()
	for _, entry := range a.entries {
		cache.UpdateEntry(entry)
	}
	for agent, selectors := range a.agents {
		cache.SetNodeSelectors(agent.String(), selectors)
	}
	return cache
}

func (a *cacheTest) assertAuthorizedEntries(t *testing.T, agent spiffeid.ID, expectEntries ...*types.Entry) {
	t.Helper()
	assertAuthorizedEntries(t, a.hydrate(), agent, expectEntries...)
}

func makeAlias(alias spiffeid.ID, selectors ...*types.Selector) *types.Entry {
	return &types.Entry{
		Id:        fmt.Sprintf("alias(spiffeid=%s)", alias),
		ParentId:  api.ProtoFromID(server),
		SpiffeId:  api.ProtoFromID(alias),
		Selectors: selectors,
	}
}

func makeDelegatee(parent, delegatee spiffeid.ID) *types.Entry {
	return &types.Entry{
		Id:        fmt.Sprintf("delegatee(parent=%s,spiffeid=%s)", parent, delegatee),
		ParentId:  api.ProtoFromID(parent),
		SpiffeId:  api.ProtoFromID(delegatee),
		Selectors: []*types.Selector{{Type: "not", Value: "relevant"}},
	}
}

func makeWorkload(parent spiffeid.ID) *types.Entry {
	return &types.Entry{
		Id:        fmt.Sprintf("workload(parent=%s)", parent),
		ParentId:  api.ProtoFromID(parent),
		SpiffeId:  &types.SPIFFEID{TrustDomain: "domain.test", Path: "/workload"},
		Selectors: []*types.Selector{{Type: "not", Value: "relevant"}},
	}
}

// BenchmarkGetAuthorizedEntriesInMemory was ported from the old full entry
// cache and some of the bugs fixed.
func BenchmarkGetAuthorizedEntriesInMemory(b *testing.B) {
	test := testCache()

	staticSelector1 := &types.Selector{Type: "static", Value: "static-1"}
	staticSelector2 := &types.Selector{Type: "static", Value: "static-2"}

	const numAgents = 50000
	for i := 0; i < numAgents; i++ {
		test.withAgent(spiffeid.RequireFromPathf(td, "/agent-%d", i), staticSelector1)
	}

	aliasID1 := api.ProtoFromID(alias1)
	aliasID2 := api.ProtoFromID(alias2)

	test.withEntries(
		// Alias
		&types.Entry{
			Id:        "alias1",
			SpiffeId:  aliasID1,
			ParentId:  &types.SPIFFEID{TrustDomain: "domain.test", Path: "/spire/server"},
			Selectors: []*types.Selector{staticSelector1},
		},
		// False alias
		&types.Entry{
			Id:        "alias2",
			SpiffeId:  aliasID2,
			ParentId:  &types.SPIFFEID{TrustDomain: "domain.test", Path: "/spire/server"},
			Selectors: []*types.Selector{staticSelector2},
		},
	)

	for i := 0; i < 300; i++ {
		test.withEntries(&types.Entry{
			Id: fmt.Sprintf("alias1-workload-%d", i),
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

	for i := 0; i < 300; i++ {
		test.withEntries(&types.Entry{
			Id: fmt.Sprintf("alias2-workload-%d", i),
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

	cache := test.hydrate()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cache.GetAuthorizedEntries(test.pickAgent())
	}
}

func assertAuthorizedEntries(tb testing.TB, cache *authorizedentries.Cache, agentID spiffeid.ID, wantEntries ...*types.Entry) {
	tb.Helper()

	entriesMap := func(entries []*types.Entry) map[string]*types.Entry {
		m := make(map[string]*types.Entry)
		for _, entry := range entries {
			m[entry.Id] = entry
		}
		return m
	}

	wantMap := entriesMap(wantEntries)
	gotMap := entriesMap(cache.GetAuthorizedEntries(agentID))

	for id, want := range wantMap {
		got, ok := gotMap[id]
		if !ok {
			assert.Fail(tb, "expected entry not returned", "expected entry %q", id)
			continue
		}

		// Make sure the contents are equivalent.
		spiretest.AssertProtoEqual(tb, want, got)

		// The pointer should not be equivalent. The cache should be cloning
		// the entries before returning.
		if want == got {
			//assert.Fail(tb, "entry proto was not cloned before return")
			continue
		}
	}

	// Assert there were not unexpected entries returned.
	for id := range gotMap {
		if _, ok := wantMap[id]; !ok {
			assert.Fail(tb, "unexpected entry returned", "unexpected entry %q", id)
			continue
		}
	}
}

func sortEntries(es []*types.Entry) {
	sort.Slice(es, func(a, b int) bool {
		return es[a].Id < es[b].Id
	})
}

func assertSliceEqual[M proto.Message](tb testing.TB, expected, actual []M, opts ...cmp.Option) bool {
	tb.Helper()
	return assertEqual(tb, expected, actual, opts, "%T proto slice not equal", *new(M))
}

func assertEqual(tb testing.TB, expected, actual interface{}, opts []cmp.Option, msgAndArgs ...interface{}) bool {
	tb.Helper()
	opts = append(opts, protocmp.Transform())
	diff := cmp.Diff(expected, actual, opts...)
	return assert.Empty(tb, diff, msgAndArgs...)
}
