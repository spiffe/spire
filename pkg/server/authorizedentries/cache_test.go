package authorizedentries

import (
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	td        = spiffeid.RequireTrustDomainFromString("domain.test")
	server    = spiffeid.RequireFromPath(td, idutil.ServerIDPath)
	agent1    = spiffeid.RequireFromPath(td, "/spire/agent/1")
	agent2    = spiffeid.RequireFromPath(td, "/spire/agent/2")
	agent3    = spiffeid.RequireFromPath(td, "/spire/agent/3")
	agent4    = spiffeid.RequireFromPath(td, "/spire/agent/4")
	delegatee = spiffeid.RequireFromPath(td, "/delegatee")
	alias1    = spiffeid.RequireFromPath(td, "/alias/1")
	alias2    = spiffeid.RequireFromPath(td, "/alias/2")
	sel1      = &types.Selector{Type: "S", Value: "1"}
	sel2      = &types.Selector{Type: "S", Value: "2"}
	sel3      = &types.Selector{Type: "S", Value: "3"}
	now       = time.Now().Truncate(time.Second)
)

func TestGetAuthorizedEntries(t *testing.T) {
	t.Run("empty cache", func(t *testing.T) {
		testCache().assertAuthorizedEntries(t, agent1)
	})

	t.Run("agent not attested still returns direct children", func(t *testing.T) {
		var (
			directChild = makeWorkload(agent1)
		)
		testCache().
			withEntries(directChild).
			assertAuthorizedEntries(t, agent1, directChild)
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
			withEntries(workload).hydrate(t)
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
			hydrate(t)

		cache.RemoveEntry(aliasEntry.Id)
		assertAuthorizedEntries(t, cache, agent1)
	})

	t.Run("agent removed", func(t *testing.T) {
		var (
			aliasEntry    = makeAlias(alias1, sel1, sel2)
			workloadEntry = makeWorkload(alias1)
		)

		cache := testCache().
			withEntries(workloadEntry, aliasEntry).
			withAgent(agent1, sel1, sel2).
			hydrate(t)

		cache.RemoveAgent(agent1.String())
		assertAuthorizedEntries(t, cache, agent1)
	})

	t.Run("agent pruned after expiry", func(t *testing.T) {
		var (
			aliasEntry    = makeAlias(alias1, sel1, sel2)
			workloadEntry = makeWorkload(alias1)
		)

		cache := testCache().
			withEntries(workloadEntry, aliasEntry).
			withExpiredAgent(agent1, time.Hour, sel1, sel2).
			withExpiredAgent(agent2, time.Hour, sel1, sel2).
			withExpiredAgent(agent3, time.Hour*2, sel1, sel2).
			withAgent(agent4, sel1, sel2).
			hydrate(t)
		assertAuthorizedEntries(t, cache, agent1, workloadEntry)
		assertAuthorizedEntries(t, cache, agent2, workloadEntry)
		assertAuthorizedEntries(t, cache, agent3, workloadEntry)
		assertAuthorizedEntries(t, cache, agent4, workloadEntry)

		assert.Equal(t, 3, cache.PruneExpiredAgents())

		assertAuthorizedEntries(t, cache, agent1)
		assertAuthorizedEntries(t, cache, agent2)
		assertAuthorizedEntries(t, cache, agent3)
		assertAuthorizedEntries(t, cache, agent4, workloadEntry)
	})
}

func TestCacheInternalStats(t *testing.T) {
	// This test asserts that the internal indexes are properly maintained
	// across various operations. The motivation is to ensure that as the cache
	// is updated that we are appropriately inserting and removing records from
	// the indexees.
	clk := clock.NewMock(t)
	t.Run("pristine", func(t *testing.T) {
		cache := NewCache(clk)
		require.Zero(t, cache.Stats())
	})

	t.Run("entries and aliases", func(t *testing.T) {
		entry1 := makeWorkload(agent1)
		entry2a := makeWorkload(agent2)

		// Version b will change to an alias instead
		entry2b := makeAlias(alias1, sel1, sel2)
		entry2b.Id = entry2a.Id

		cache := NewCache(clk)
		cache.UpdateEntry(entry1)
		require.Equal(t, CacheStats{
			EntriesByEntryID:  1,
			EntriesByParentID: 1,
		}, cache.Stats())

		cache.UpdateEntry(entry2a)
		require.Equal(t, CacheStats{
			EntriesByEntryID:  2,
			EntriesByParentID: 2,
		}, cache.Stats())

		cache.UpdateEntry(entry2b)
		require.Equal(t, CacheStats{
			EntriesByEntryID:  1,
			EntriesByParentID: 1,
			AliasesByEntryID:  2, // one for each selector
			AliasesBySelector: 2, // one for each selector
		}, cache.Stats())

		cache.RemoveEntry(entry1.Id)
		require.Equal(t, CacheStats{
			AliasesByEntryID:  2, // one for each selector
			AliasesBySelector: 2, // one for each selector
		}, cache.Stats())

		cache.RemoveEntry(entry2b.Id)
		require.Zero(t, cache.Stats())

		// Remove again and make sure nothing happens.
		cache.RemoveEntry(entry2b.Id)
		require.Zero(t, cache.Stats())
	})

	t.Run("agents", func(t *testing.T) {
		cache := NewCache(clk)
		cache.UpdateAgent(agent1.String(), now.Add(time.Hour), []*types.Selector{sel1})
		require.Equal(t, CacheStats{
			AgentsByID:        1,
			AgentsByExpiresAt: 1,
		}, cache.Stats())

		cache.UpdateAgent(agent2.String(), now.Add(time.Hour*2), []*types.Selector{sel2})
		require.Equal(t, CacheStats{
			AgentsByID:        2,
			AgentsByExpiresAt: 2,
		}, cache.Stats())

		cache.UpdateAgent(agent2.String(), now.Add(time.Hour*3), []*types.Selector{sel2})
		require.Equal(t, CacheStats{
			AgentsByID:        2,
			AgentsByExpiresAt: 2,
		}, cache.Stats())

		cache.RemoveAgent(agent1.String())
		require.Equal(t, CacheStats{
			AgentsByID:        1,
			AgentsByExpiresAt: 1,
		}, cache.Stats())

		cache.RemoveAgent(agent2.String())
		require.Zero(t, cache.Stats())
	})
}

func testCache() *cacheTest {
	return &cacheTest{
		entries: make(map[string]*types.Entry),
		agents:  make(map[spiffeid.ID]agentInfo),
	}
}

type cacheTest struct {
	entries map[string]*types.Entry
	agents  map[spiffeid.ID]agentInfo
}

type agentInfo struct {
	ExpiresAt time.Time
	Selectors []*types.Selector
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
	expiresAt := now.Add(time.Hour * time.Duration(1+len(a.agents)))
	a.agents[node] = agentInfo{
		ExpiresAt: expiresAt,
		Selectors: append([]*types.Selector(nil), selectors...),
	}
	return a
}

func (a *cacheTest) withExpiredAgent(node spiffeid.ID, expiredBy time.Duration, selectors ...*types.Selector) *cacheTest {
	expiresAt := now.Add(-expiredBy)
	a.agents[node] = agentInfo{
		ExpiresAt: expiresAt,
		Selectors: append([]*types.Selector(nil), selectors...),
	}
	return a
}

func (a *cacheTest) hydrate(tb testing.TB) *Cache {
	clk := clock.NewMock(tb)
	cache := NewCache(clk)
	for _, entry := range a.entries {
		cache.UpdateEntry(entry)
	}
	for agent, info := range a.agents {
		cache.UpdateAgent(agent.String(), info.ExpiresAt, info.Selectors)
	}
	return cache
}

func (a *cacheTest) assertAuthorizedEntries(t *testing.T, agent spiffeid.ID, expectEntries ...*types.Entry) {
	t.Helper()
	assertAuthorizedEntries(t, a.hydrate(t), agent, expectEntries...)
}

func makeAlias(alias spiffeid.ID, selectors ...*types.Selector) *types.Entry {
	return &types.Entry{
		Id:        fmt.Sprintf("alias-%d(spiffeid=%s)", makeEntryIDPrefix(), alias),
		ParentId:  api.ProtoFromID(server),
		SpiffeId:  api.ProtoFromID(alias),
		Selectors: selectors,
	}
}

func makeDelegatee(parent, delegatee spiffeid.ID) *types.Entry {
	return &types.Entry{
		Id:        fmt.Sprintf("delegatee-%d(parent=%s,spiffeid=%s)", makeEntryIDPrefix(), parent, delegatee),
		ParentId:  api.ProtoFromID(parent),
		SpiffeId:  api.ProtoFromID(delegatee),
		Selectors: []*types.Selector{{Type: "not", Value: "relevant"}},
	}
}

func makeWorkload(parent spiffeid.ID) *types.Entry {
	return &types.Entry{
		Id:        fmt.Sprintf("workload-%d(parent=%s)", makeEntryIDPrefix(), parent),
		ParentId:  api.ProtoFromID(parent),
		SpiffeId:  &types.SPIFFEID{TrustDomain: "domain.test", Path: "/workload"},
		Selectors: []*types.Selector{{Type: "not", Value: "relevant"}},
	}
}

var nextEntryIDPrefix int32

func makeEntryIDPrefix() int32 {
	return atomic.AddInt32(&nextEntryIDPrefix, 1)
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
			ParentId:  &types.SPIFFEID{TrustDomain: "domain.test", Path: idutil.ServerIDPath},
			Selectors: []*types.Selector{staticSelector1},
		},
		// False alias
		&types.Entry{
			Id:        "alias2",
			SpiffeId:  aliasID2,
			ParentId:  &types.SPIFFEID{TrustDomain: "domain.test", Path: idutil.ServerIDPath},
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

	cache := test.hydrate(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cache.GetAuthorizedEntries(test.pickAgent())
	}
}

func assertAuthorizedEntries(tb testing.TB, cache *Cache, agentID spiffeid.ID, wantEntries ...*types.Entry) {
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
			assert.Fail(tb, "entry proto was not cloned before return")
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
