package endpoints

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/pkg/server/authorizedentries"
	"github.com/spiffe/spire/pkg/server/cache/nodecache"
	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/fakes/fakedatastore"
	"github.com/spiffe/spire/test/fakes/fakemetrics"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewAuthorizedEntryFetcherEvents(t *testing.T) {
	ctx := context.Background()
	log, _ := test.NewNullLogger()
	clk := clock.NewMock(t)
	ds := fakedatastore.New(t)
	metrics := fakemetrics.New()

	nodeCache, err := nodecache.New(ctx, log, ds, clk, false, true)
	require.Nil(t, err)

	ef, err := NewAuthorizedEntryFetcherEvents(ctx, AuthorizedEntryFetcherEventsConfig{
		log:                     log,
		metrics:                 metrics,
		clk:                     clk,
		nodeCache:               nodeCache,
		ds:                      ds,
		cacheReloadInterval:     defaultCacheReloadInterval,
		fullCacheReloadInterval: defaultFullCacheReloadInterval,
		pruneEventsOlderThan:    defaultPruneEventsOlderThan,
		eventTimeout:            defaultEventTimeout,
	})
	assert.NoError(t, err)
	assert.NotNil(t, ef)

	buildMetrics := []fakemetrics.MetricItem{
		agentsByIDMetric(0),
		agentsByIDExpiresAtMetric(0),
		nodeAliasesByEntryIDMetric(0),
		nodeAliasesBySelectorMetric(0),
		nodeSkippedEventMetric(0),

		entriesByEntryIDMetric(0),
		entriesByParentIDMetric(0),
		entriesSkippedEventMetric(0),
	}

	assert.ElementsMatch(t, buildMetrics, metrics.AllMetrics(), "should emit metrics for node aliases, entries, and agents")
	metrics.Reset()

	agentID := spiffeid.RequireFromString("spiffe://example.org/myagent")

	_, err = ds.CreateAttestedNode(ctx, &common.AttestedNode{
		SpiffeId:     agentID.String(),
		CertNotAfter: time.Now().Add(5 * time.Hour).Unix(),
	})
	assert.NoError(t, err)

	// Also set the node selectors, since this isn't done by CreateAttestedNode
	err = ds.SetNodeSelectors(ctx, agentID.String(), []*common.Selector{
		{
			Type:  "test",
			Value: "alias",
		},
		{
			Type:  "test",
			Value: "cluster",
		},
	})
	assert.NoError(t, err)

	// Create node alias for the agent
	_, err = ds.CreateRegistrationEntry(ctx, &common.RegistrationEntry{
		SpiffeId: "spiffe://example.org/alias",
		ParentId: "spiffe://example.org/spire/server",
		Selectors: []*common.Selector{
			{
				Type:  "test",
				Value: "alias",
			},
		},
	})
	assert.NoError(t, err)

	// Create one registration entry parented to the agent directly
	entry1, err := ds.CreateRegistrationEntry(ctx, &common.RegistrationEntry{
		SpiffeId: "spiffe://example.org/viaagent",
		ParentId: agentID.String(),
		Selectors: []*common.Selector{
			{
				Type:  "workload",
				Value: "one",
			},
		},
	})
	assert.NoError(t, err)

	// Create one registration entry parented to the alias
	entry2, err := ds.CreateRegistrationEntry(ctx, &common.RegistrationEntry{
		SpiffeId: "spiffe://example.org/viaalias",
		ParentId: "spiffe://example.org/alias",
		Selectors: []*common.Selector{
			{
				Type:  "workload",
				Value: "two",
			},
		},
	})
	assert.NoError(t, err)

	err = ef.updateCache(ctx)
	assert.NoError(t, err)

	entries, err := ef.FetchAuthorizedEntries(ctx, agentID)
	assert.NoError(t, err)
	compareEntries(t, entries, entry1, entry2)

	// Assert metrics
	expectedMetrics := []fakemetrics.MetricItem{
		agentsByIDMetric(1),
		agentsByIDExpiresAtMetric(1),
		nodeAliasesByEntryIDMetric(1),
		nodeAliasesBySelectorMetric(1),
		entriesByEntryIDMetric(2),
		entriesByParentIDMetric(2),
	}

	assert.ElementsMatch(t, expectedMetrics, metrics.AllMetrics(), "should emit metrics for node aliases, entries, and agents")
}

func TestNewAuthorizedEntryFetcherEventsErrorBuildingCache(t *testing.T) {
	ctx := context.Background()
	log, _ := test.NewNullLogger()
	clk := clock.NewMock(t)
	ds := fakedatastore.New(t)
	metrics := fakemetrics.New()

	buildErr := errors.New("build error")
	ds.SetNextError(buildErr)

	nodeCache, err := nodecache.New(ctx, log, ds, clk, false, true)
	require.Nil(t, err)

	ef, err := NewAuthorizedEntryFetcherEvents(ctx, AuthorizedEntryFetcherEventsConfig{
		log:                     log,
		metrics:                 metrics,
		clk:                     clk,
		ds:                      ds,
		nodeCache:               nodeCache,
		cacheReloadInterval:     defaultCacheReloadInterval,
		fullCacheReloadInterval: defaultFullCacheReloadInterval,
		pruneEventsOlderThan:    defaultPruneEventsOlderThan,
		eventTimeout:            defaultEventTimeout,
	})
	assert.Error(t, err)
	assert.Nil(t, ef)

	// Assert metrics
	expectedMetrics := []fakemetrics.MetricItem{}
	assert.ElementsMatch(t, expectedMetrics, metrics.AllMetrics(), "should emit no metrics")
}

func TestBuildCacheSavesSkippedEvents(t *testing.T) {
	ctx := context.Background()
	log, _ := test.NewNullLogger()
	clk := clock.NewMock(t)
	ds := fakedatastore.New(t)
	metrics := fakemetrics.New()

	// Create Registration Entry Events with a gap
	err := ds.CreateRegistrationEntryEventForTesting(ctx, &datastore.RegistrationEntryEvent{
		EventID: 1,
		EntryID: "test",
	})
	require.NoError(t, err)

	err = ds.CreateRegistrationEntryEventForTesting(ctx, &datastore.RegistrationEntryEvent{
		EventID: 3,
		EntryID: "test",
	})
	require.NoError(t, err)

	// Create AttestedNode Events with a gap
	err = ds.CreateAttestedNodeEventForTesting(ctx, &datastore.AttestedNodeEvent{
		EventID:  1,
		SpiffeID: "test",
	})
	require.NoError(t, err)

	err = ds.CreateAttestedNodeEventForTesting(ctx, &datastore.AttestedNodeEvent{
		EventID:  4,
		SpiffeID: "test",
	})
	require.NoError(t, err)

	nodeCache, err := nodecache.New(ctx, log, ds, clk, false, true)
	require.Nil(t, err)

	cache := authorizedentries.NewCache(clk)

	registrationEntries, err := buildRegistrationEntriesCache(ctx, log, metrics, ds, clk, cache, pageSize, defaultCacheReloadInterval, defaultEventTimeout)
	require.NoError(t, err)
	require.NotNil(t, registrationEntries)

	attestedNodes, err := buildAttestedNodesCache(ctx, log, metrics, ds, clk, cache, nodeCache, defaultCacheReloadInterval, defaultEventTimeout)
	require.NoError(t, err)
	require.NotNil(t, attestedNodes)

	assert.Contains(t, registrationEntries.eventTracker.events, uint(2))
	assert.Equal(t, uint(3), registrationEntries.lastEvent)

	assert.Contains(t, attestedNodes.eventTracker.events, uint(2))
	assert.Contains(t, attestedNodes.eventTracker.events, uint(3))
	assert.Equal(t, uint(4), attestedNodes.lastEvent)

	// Assert zero metrics since the updateCache() method doesn't get called right at built time.
	expectedMetrics := []fakemetrics.MetricItem{
		agentsByIDMetric(0),
		agentsByIDExpiresAtMetric(0),
		nodeAliasesByEntryIDMetric(0),
		nodeAliasesBySelectorMetric(0),
		nodeSkippedEventMetric(2),

		entriesByEntryIDMetric(0),
		entriesByParentIDMetric(0),
		entriesSkippedEventMetric(1),
	}
	assert.ElementsMatch(t, expectedMetrics, metrics.AllMetrics(), "should emit no metrics")
}

func TestRunUpdateCacheTaskDoesFullUpdate(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	log, _ := test.NewNullLogger()
	log.SetLevel(logrus.DebugLevel)
	clk := clock.NewMock(t)
	ds := fakedatastore.New(t)
	metrics := fakemetrics.New()

	ef, err := NewAuthorizedEntryFetcherEvents(ctx, AuthorizedEntryFetcherEventsConfig{
		log:                     log,
		metrics:                 metrics,
		clk:                     clk,
		ds:                      ds,
		cacheReloadInterval:     3 * time.Second,
		fullCacheReloadInterval: 5 * time.Second,
		pruneEventsOlderThan:    defaultPruneEventsOlderThan,
		eventTimeout:            defaultEventTimeout,
	})
	require.NoError(t, err)
	require.NotNil(t, ef)

	ef.mu.RLock()
	initialCache := ef.cache
	ef.mu.RUnlock()

	// Start Update Task
	updateCacheTaskErr := make(chan error)
	go func() {
		updateCacheTaskErr <- ef.RunUpdateCacheTask(ctx)
	}()
	clk.WaitForTickerMulti(time.Second, 2, "waiting to create tickers")

	// First iteration, cache should not be rebuilt
	clk.Add(4 * time.Second)
	ef.mu.RLock()
	require.Equal(t, initialCache, ef.cache)
	ef.mu.RUnlock()

	// Second iteration, cache should be rebuilt
	// First we wait for the fullCacheReloadTicker to
	// set the fullCacheReload flag to true
	clk.Add(5 * time.Second)
	// And then once a gain wait some more for the
	// cache reload ticker to tick again.
	clk.Add(6 * time.Second)
	ef.mu.RLock()
	require.NotEqual(t, initialCache, ef.cache)
	ef.mu.RUnlock()

	// Stop the task
	cancel()
	err = <-updateCacheTaskErr
	require.ErrorIs(t, err, context.Canceled)
}

func TestRunUpdateCacheTaskPrunesExpiredAgents(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	log, hook := test.NewNullLogger()
	log.SetLevel(logrus.DebugLevel)
	clk := clock.NewMock(t)
	ds := fakedatastore.New(t)
	metrics := fakemetrics.New()

	nodeCache, err := nodecache.New(ctx, log, ds, clk, false, true)
	require.Nil(t, err)

	ef, err := NewAuthorizedEntryFetcherEvents(ctx, AuthorizedEntryFetcherEventsConfig{
		log:                     log,
		metrics:                 metrics,
		clk:                     clk,
		ds:                      ds,
		nodeCache:               nodeCache,
		cacheReloadInterval:     defaultCacheReloadInterval,
		fullCacheReloadInterval: defaultFullCacheReloadInterval,
		pruneEventsOlderThan:    defaultPruneEventsOlderThan,
		eventTimeout:            defaultEventTimeout,
	})
	require.NoError(t, err)
	require.NotNil(t, ef)

	agentID := spiffeid.RequireFromString("spiffe://example.org/myagent")

	// Start Update Task
	updateCacheTaskErr := make(chan error)
	go func() {
		updateCacheTaskErr <- ef.RunUpdateCacheTask(ctx)
	}()
	clk.WaitForTickerMulti(time.Second, 2, "waiting to create tickers")
	entries, err := ef.FetchAuthorizedEntries(ctx, agentID)
	assert.NoError(t, err)
	require.Zero(t, entries)

	// Create Attested Node and Registration Entry
	_, err = ds.CreateAttestedNode(ctx, &common.AttestedNode{
		SpiffeId:     agentID.String(),
		CertNotAfter: clk.Now().Add(6 * time.Second).Unix(),
	})
	assert.NoError(t, err)

	entry, err := ds.CreateRegistrationEntry(ctx, &common.RegistrationEntry{
		SpiffeId: "spiffe://example.org/workload",
		ParentId: agentID.String(),
		Selectors: []*common.Selector{
			{
				Type:  "workload",
				Value: "one",
			},
		},
	})
	assert.NoError(t, err)

	// Bump clock and rerun UpdateCacheTask
	clk.Add(defaultCacheReloadInterval)
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		entries, err = ef.FetchAuthorizedEntries(ctx, agentID)
		assert.NoError(c, err)
	}, time.Second, 50*time.Millisecond)
	compareEntries(t, entries, entry)

	// Make sure nothing was pruned yet
	for _, entry := range hook.AllEntries() {
		require.NotEqual(t, "Pruned expired agents from entry cache", entry.Message)
	}

	// Bump clock so entry expires and is pruned
	clk.Add(defaultCacheReloadInterval)
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.Equal(c, 1, hook.LastEntry().Data["count"])
		assert.Equal(c, "Pruned expired agents from entry cache", hook.LastEntry().Message)
	}, time.Second, 50*time.Millisecond)

	// Stop the task
	cancel()
	err = <-updateCacheTaskErr
	require.ErrorIs(t, err, context.Canceled)
}

func TestUpdateRegistrationEntriesCacheSkippedEvents(t *testing.T) {
	ctx := context.Background()
	log, _ := test.NewNullLogger()
	clk := clock.NewMock(t)
	ds := fakedatastore.New(t)
	metrics := fakemetrics.New()

	nodeCache, err := nodecache.New(ctx, log, ds, clk, false, true)
	require.Nil(t, err)

	ef, err := NewAuthorizedEntryFetcherEvents(ctx, AuthorizedEntryFetcherEventsConfig{
		log:                     log,
		metrics:                 metrics,
		clk:                     clk,
		ds:                      ds,
		nodeCache:               nodeCache,
		cacheReloadInterval:     defaultCacheReloadInterval,
		fullCacheReloadInterval: defaultFullCacheReloadInterval,
		pruneEventsOlderThan:    defaultPruneEventsOlderThan,
		eventTimeout:            defaultEventTimeout,
	})
	require.NoError(t, err)
	require.NotNil(t, ef)

	agentID := spiffeid.RequireFromString("spiffe://example.org/myagent")

	// Ensure no entries are in there to start
	entries, err := ef.FetchAuthorizedEntries(ctx, agentID)
	require.NoError(t, err)
	require.Zero(t, entries)

	// Create Initial Registration Entry
	entry1, err := ds.CreateRegistrationEntry(ctx, &common.RegistrationEntry{
		SpiffeId: "spiffe://example.org/workload",
		ParentId: agentID.String(),
		Selectors: []*common.Selector{
			{
				Type:  "workload",
				Value: "one",
			},
		},
	})
	require.NoError(t, err)

	// Ensure it gets added to cache
	err = ef.updateCache(ctx)
	require.NoError(t, err)

	entries, err = ef.FetchAuthorizedEntries(ctx, agentID)
	require.NoError(t, err)
	compareEntries(t, entries, entry1)

	// Delete initial registration entry
	_, err = ds.DeleteRegistrationEntry(ctx, entry1.EntryId)
	require.NoError(t, err)

	// Delete the event for now and then add it back later to simulate out of order events
	err = ds.DeleteRegistrationEntryEventForTesting(ctx, 2)
	require.NoError(t, err)

	// Create Second entry
	entry2, err := ds.CreateRegistrationEntry(ctx, &common.RegistrationEntry{
		SpiffeId: "spiffe://example.org/workload2",
		ParentId: agentID.String(),
		Selectors: []*common.Selector{
			{
				Type:  "workload",
				Value: "two",
			},
		},
	})
	require.NoError(t, err)

	// Check second entry is added to cache
	err = ef.updateCache(ctx)
	require.NoError(t, err)

	entries, err = ef.FetchAuthorizedEntries(ctx, agentID)
	require.NoError(t, err)
	compareEntries(t, entries, entry1, entry2)

	// Add back in deleted event
	err = ds.CreateRegistrationEntryEventForTesting(ctx, &datastore.RegistrationEntryEvent{
		EventID: 2,
		EntryID: entry1.EntryId,
	})
	require.NoError(t, err)

	// Make sure it gets processed and the initial entry is deleted
	err = ef.updateCache(ctx)
	require.NoError(t, err)

	entries, err = ef.FetchAuthorizedEntries(ctx, agentID)
	require.NoError(t, err)
	compareEntries(t, entries, entry2)
}

func TestUpdateRegistrationEntriesCacheSkippedStartupEvents(t *testing.T) {
	ctx := context.Background()
	log, _ := test.NewNullLogger()
	clk := clock.NewMock(t)
	ds := fakedatastore.New(t)
	metrics := fakemetrics.New()

	agentID := spiffeid.RequireFromString("spiffe://example.org/myagent")

	// Create First Registration Entry
	entry1, err := ds.CreateRegistrationEntry(ctx, &common.RegistrationEntry{
		SpiffeId: "spiffe://example.org/workload",
		ParentId: agentID.String(),
		Selectors: []*common.Selector{
			{
				Type:  "workload",
				Value: "one",
			},
		},
	})
	require.NoError(t, err)

	// Delete the create event for the first entry
	err = ds.DeleteRegistrationEntryEventForTesting(ctx, 1)
	require.NoError(t, err)

	_, err = ds.DeleteRegistrationEntry(ctx, entry1.EntryId)
	require.NoError(t, err)

	// Delete the delete event for the first entry
	err = ds.DeleteRegistrationEntryEventForTesting(ctx, 2)
	require.NoError(t, err)

	// Create Second entry
	entry2, err := ds.CreateRegistrationEntry(ctx, &common.RegistrationEntry{
		SpiffeId: "spiffe://example.org/workload2",
		ParentId: agentID.String(),
		Selectors: []*common.Selector{
			{
				Type:  "workload",
				Value: "two",
			},
		},
	})
	require.NoError(t, err)

	// Create entry fetcher
	nodeCache, err := nodecache.New(ctx, log, ds, clk, false, true)
	require.Nil(t, err)

	ef, err := NewAuthorizedEntryFetcherEvents(ctx, AuthorizedEntryFetcherEventsConfig{
		log:                     log,
		metrics:                 metrics,
		clk:                     clk,
		ds:                      ds,
		nodeCache:               nodeCache,
		cacheReloadInterval:     defaultCacheReloadInterval,
		fullCacheReloadInterval: defaultFullCacheReloadInterval,
		pruneEventsOlderThan:    defaultPruneEventsOlderThan,
		eventTimeout:            defaultEventTimeout,
	})
	require.NoError(t, err)
	require.NotNil(t, ef)

	// Ensure there is 1 entry to start
	entries, err := ef.FetchAuthorizedEntries(ctx, agentID)
	require.NoError(t, err)
	require.Equal(t, 1, len(entries))
	require.Equal(t, entry2.EntryId, entries[0].GetId())
	require.Equal(t, entry2.SpiffeId, idutil.RequireIDProtoString(entries[0].GetSpiffeId()))

	// Recreate First Registration Entry and delete the event associated with this create
	entry1, err = ds.CreateRegistrationEntry(ctx, &common.RegistrationEntry{
		SpiffeId: "spiffe://example.org/workload",
		ParentId: agentID.String(),
		Selectors: []*common.Selector{
			{
				Type:  "workload",
				Value: "one",
			},
		},
	})
	require.NoError(t, err)

	err = ds.DeleteRegistrationEntryEventForTesting(ctx, 4)
	require.NoError(t, err)

	// Update cache
	err = ef.updateCache(ctx)
	require.NoError(t, err)

	// Still should be 1 entry, no event tells us about spiffe://example.org/workload
	entries, err = ef.FetchAuthorizedEntries(ctx, agentID)
	require.NoError(t, err)
	require.Equal(t, 1, len(entries))
	require.Equal(t, entry2.EntryId, entries[0].GetId())
	require.Equal(t, entry2.SpiffeId, idutil.RequireIDProtoString(entries[0].GetSpiffeId()))

	// Add back in first event
	err = ds.CreateRegistrationEntryEventForTesting(ctx, &datastore.RegistrationEntryEvent{
		EventID: 1,
		EntryID: entry1.EntryId,
	})
	require.NoError(t, err)

	// Update cache
	err = ef.updateCache(ctx)
	require.NoError(t, err)

	// Should be 2 entries now
	entries, err = ef.FetchAuthorizedEntries(ctx, agentID)
	require.NoError(t, err)
	require.Equal(t, 2, len(entries))

	entryIDs := make([]string, 0, 2)
	spiffeIDs := make([]string, 0, 2)
	for _, entry := range entries {
		entryIDs = append(entryIDs, entry.GetId())
		spiffeIDs = append(spiffeIDs, idutil.RequireIDProtoString(entry.GetSpiffeId()))
	}
	require.Contains(t, entryIDs, entry1.EntryId)
	require.Contains(t, entryIDs, entry2.EntryId)
	require.Contains(t, spiffeIDs, entry1.SpiffeId)
	require.Contains(t, spiffeIDs, entry2.SpiffeId)
}

func TestUpdateAttestedNodesCacheSkippedEvents(t *testing.T) {
	ctx := context.Background()
	log, _ := test.NewNullLogger()
	clk := clock.NewMock(t)
	ds := fakedatastore.New(t)
	metrics := fakemetrics.New()

	nodeCache, err := nodecache.New(ctx, log, ds, clk, false, true)
	require.Nil(t, err)

	ef, err := NewAuthorizedEntryFetcherEvents(ctx, AuthorizedEntryFetcherEventsConfig{
		log:                     log,
		metrics:                 metrics,
		clk:                     clk,
		ds:                      ds,
		nodeCache:               nodeCache,
		cacheReloadInterval:     defaultCacheReloadInterval,
		fullCacheReloadInterval: defaultFullCacheReloadInterval,
		pruneEventsOlderThan:    defaultPruneEventsOlderThan,
		eventTimeout:            defaultEventTimeout,
	})
	require.NoError(t, err)
	require.NotNil(t, ef)

	agent1 := spiffeid.RequireFromString("spiffe://example.org/myagent1")
	agent2 := spiffeid.RequireFromString("spiffe://example.org/myagent2")

	// Ensure no entries are in there to start
	entries, err := ef.FetchAuthorizedEntries(ctx, agent2)
	require.NoError(t, err)
	require.Zero(t, entries)

	// Create node alias for agent 2
	alias, err := ds.CreateRegistrationEntry(ctx, &common.RegistrationEntry{
		SpiffeId: "spiffe://example.org/alias",
		ParentId: "spiffe://example.org/spire/server",
		Selectors: []*common.Selector{
			{
				Type:  "test",
				Value: "alias",
			},
		},
	})
	assert.NoError(t, err)

	// Create a registration entry parented to the alias
	entry, err := ds.CreateRegistrationEntry(ctx, &common.RegistrationEntry{
		SpiffeId: "spiffe://example.org/viaalias",
		ParentId: alias.SpiffeId,
		Selectors: []*common.Selector{
			{
				Type:  "workload",
				Value: "two",
			},
		},
	})
	assert.NoError(t, err)

	// Create both Attested Nodes
	_, err = ds.CreateAttestedNode(ctx, &common.AttestedNode{
		SpiffeId:     agent1.String(),
		CertNotAfter: time.Now().Add(5 * time.Hour).Unix(),
	})
	require.NoError(t, err)

	_, err = ds.CreateAttestedNode(ctx, &common.AttestedNode{
		SpiffeId:     agent2.String(),
		CertNotAfter: time.Now().Add(5 * time.Hour).Unix(),
	})
	require.NoError(t, err)

	// Create selectors for agent 2
	err = ds.SetNodeSelectors(ctx, agent2.String(), []*common.Selector{
		{
			Type:  "test",
			Value: "alias",
		},
		{
			Type:  "test",
			Value: "cluster2",
		},
	})
	assert.NoError(t, err)

	// Create selectors for agent 1
	err = ds.SetNodeSelectors(ctx, agent1.String(), []*common.Selector{
		{
			Type:  "test",
			Value: "cluster1",
		},
	})
	assert.NoError(t, err)

	// Delete the events for agent 2 for now and then add it back later to simulate out of order events
	err = ds.DeleteAttestedNodeEventForTesting(ctx, 2)
	require.NoError(t, err)
	err = ds.DeleteAttestedNodeEventForTesting(ctx, 3)
	require.NoError(t, err)

	// Should not be in cache yet
	err = ef.updateCache(ctx)
	require.NoError(t, err)

	entries, err = ef.FetchAuthorizedEntries(ctx, agent2)
	require.NoError(t, err)
	require.Equal(t, 0, len(entries))

	// Add back in deleted events
	err = ds.CreateAttestedNodeEventForTesting(ctx, &datastore.AttestedNodeEvent{
		EventID:  2,
		SpiffeID: agent2.String(),
	})
	require.NoError(t, err)
	err = ds.CreateAttestedNodeEventForTesting(ctx, &datastore.AttestedNodeEvent{
		EventID:  3,
		SpiffeID: agent2.String(),
	})
	require.NoError(t, err)

	// Make sure it gets processed and the initial entry is deleted
	err = ef.updateCache(ctx)
	require.NoError(t, err)

	entries, err = ef.FetchAuthorizedEntries(ctx, agent2)
	require.NoError(t, err)
	compareEntries(t, entries, entry)
}

func TestUpdateAttestedNodesCacheSkippedStartupEvents(t *testing.T) {
	ctx := context.Background()
	log, _ := test.NewNullLogger()
	clk := clock.NewMock(t)
	ds := fakedatastore.New(t)
	metrics := fakemetrics.New()

	agent1 := spiffeid.RequireFromString("spiffe://example.org/myagent1")
	agent2 := spiffeid.RequireFromString("spiffe://example.org/myagent2")

	// Create node alias for agent
	alias, err := ds.CreateRegistrationEntry(ctx, &common.RegistrationEntry{
		SpiffeId: "spiffe://example.org/alias",
		ParentId: "spiffe://example.org/spire/server",
		Selectors: []*common.Selector{
			{
				Type:  "test",
				Value: "alias",
			},
		},
	})
	assert.NoError(t, err)

	// Create a registration entry parented to the alias
	entry, err := ds.CreateRegistrationEntry(ctx, &common.RegistrationEntry{
		SpiffeId: "spiffe://example.org/viaalias",
		ParentId: alias.SpiffeId,
		Selectors: []*common.Selector{
			{
				Type:  "workload",
				Value: "one",
			},
		},
	})
	assert.NoError(t, err)

	// Create first Attested Node and selectors
	_, err = ds.CreateAttestedNode(ctx, &common.AttestedNode{
		SpiffeId:     agent1.String(),
		CertNotAfter: time.Now().Add(5 * time.Hour).Unix(),
	})
	require.NoError(t, err)

	err = ds.SetNodeSelectors(ctx, agent1.String(), []*common.Selector{
		{
			Type:  "test",
			Value: "alias",
		},
		{
			Type:  "test",
			Value: "cluster1",
		},
	})
	assert.NoError(t, err)

	// Create second Attested Node
	_, err = ds.CreateAttestedNode(ctx, &common.AttestedNode{
		SpiffeId:     agent2.String(),
		CertNotAfter: time.Now().Add(5 * time.Hour).Unix(),
	})
	require.NoError(t, err)

	// Delete the event for creating the node or now and then add it back later to simulate out of order events
	_, err = ds.DeleteAttestedNode(ctx, agent1.String())
	require.NoError(t, err)
	err = ds.DeleteAttestedNodeEventForTesting(ctx, 1)
	require.NoError(t, err)

	// Create entry fetcher
	nodeCache, err := nodecache.New(ctx, log, ds, clk, false, true)
	require.Nil(t, err)

	ef, err := NewAuthorizedEntryFetcherEvents(ctx, AuthorizedEntryFetcherEventsConfig{
		log:                  log,
		metrics:              metrics,
		clk:                  clk,
		ds:                   ds,
		nodeCache:            nodeCache,
		cacheReloadInterval:  defaultCacheReloadInterval,
		pruneEventsOlderThan: defaultPruneEventsOlderThan,
		eventTimeout:         defaultEventTimeout,
	})
	require.NoError(t, err)
	require.NotNil(t, ef)

	err = ef.updateCache(ctx)
	require.NoError(t, err)

	// Ensure there are no entries to start
	entries, err := ef.FetchAuthorizedEntries(ctx, agent1)
	require.NoError(t, err)
	require.Zero(t, len(entries))

	// Recreate attested node and selectors for agent 1
	_, err = ds.CreateAttestedNode(ctx, &common.AttestedNode{
		SpiffeId:     agent1.String(),
		CertNotAfter: time.Now().Add(5 * time.Hour).Unix(),
	})
	require.NoError(t, err)
	err = ds.SetNodeSelectors(ctx, agent1.String(), []*common.Selector{
		{
			Type:  "test",
			Value: "alias",
		},
		{
			Type:  "test",
			Value: "cluster1",
		},
	})
	assert.NoError(t, err)

	// Delete new events
	err = ds.DeleteAttestedNodeEventForTesting(ctx, 5)
	require.NoError(t, err)
	err = ds.DeleteAttestedNodeEventForTesting(ctx, 6)
	require.NoError(t, err)

	// Update cache, should still be no entries
	err = ef.updateCache(ctx)
	require.NoError(t, err)

	entries, err = ef.FetchAuthorizedEntries(ctx, agent1)
	require.NoError(t, err)
	require.Zero(t, len(entries))

	// Add back in deleted event
	err = ds.CreateAttestedNodeEventForTesting(ctx, &datastore.AttestedNodeEvent{
		EventID:  1,
		SpiffeID: agent1.String(),
	})
	require.NoError(t, err)

	// Update cache, should be 1 entry now pointed to the alias
	err = ef.updateCache(ctx)
	require.NoError(t, err)

	entries, err = ef.FetchAuthorizedEntries(ctx, agent1)
	require.NoError(t, err)
	compareEntries(t, entries, entry)
}

func TestFullCacheReloadRecoversFromSkippedRegistrationEntryEvents(t *testing.T) {
	ctx := context.Background()
	log, _ := test.NewNullLogger()
	clk := clock.NewMock(t)
	ds := fakedatastore.New(t)
	metrics := fakemetrics.New()

	nodeCache, err := nodecache.New(ctx, log, ds, clk, false, true)
	require.Nil(t, err)

	ef, err := NewAuthorizedEntryFetcherEvents(ctx, AuthorizedEntryFetcherEventsConfig{
		log:                     log,
		metrics:                 metrics,
		clk:                     clk,
		ds:                      ds,
		nodeCache:               nodeCache,
		cacheReloadInterval:     defaultCacheReloadInterval,
		fullCacheReloadInterval: defaultFullCacheReloadInterval,
		pruneEventsOlderThan:    defaultPruneEventsOlderThan,
		eventTimeout:            defaultEventTimeout,
	})
	require.NoError(t, err)
	require.NotNil(t, ef)

	agentID := spiffeid.RequireFromString("spiffe://example.org/myagent")

	// Ensure no entries are in there to start
	entries, err := ef.FetchAuthorizedEntries(ctx, agentID)
	require.NoError(t, err)
	require.Zero(t, entries)

	// Create Initial Registration Entry
	entry1, err := ds.CreateRegistrationEntry(ctx, &common.RegistrationEntry{
		SpiffeId: "spiffe://example.org/workload",
		ParentId: agentID.String(),
		Selectors: []*common.Selector{
			{
				Type:  "workload",
				Value: "one",
			},
		},
	})
	require.NoError(t, err)

	// Ensure it gets added to cache
	err = ef.updateCache(ctx)
	require.NoError(t, err)

	entries, err = ef.FetchAuthorizedEntries(ctx, agentID)
	require.NoError(t, err)
	compareEntries(t, entries, entry1)

	// Create Second entry
	entry2, err := ds.CreateRegistrationEntry(ctx, &common.RegistrationEntry{
		SpiffeId: "spiffe://example.org/workload2",
		ParentId: agentID.String(),
		Selectors: []*common.Selector{
			{
				Type:  "workload",
				Value: "two",
			},
		},
	})
	require.NoError(t, err)

	// Delete the event
	err = ds.DeleteRegistrationEntryEventForTesting(ctx, 2)
	require.NoError(t, err)

	// Check second entry is not added to cache
	err = ef.updateCache(ctx)
	require.NoError(t, err)

	entries, err = ef.FetchAuthorizedEntries(ctx, agentID)
	require.NoError(t, err)
	compareEntries(t, entries, entry1)

	// Rebuild the cache
	err = ef.buildCache(ctx)
	require.NoError(t, err)

	// Should be 2 entries now
	entries, err = ef.FetchAuthorizedEntries(ctx, agentID)
	require.NoError(t, err)
	compareEntries(t, entries, entry1, entry2)
}

func TestFullCacheReloadRecoversFromSkippedAttestedNodeEvents(t *testing.T) {
	ctx := context.Background()
	log, _ := test.NewNullLogger()
	clk := clock.NewMock(t)
	ds := fakedatastore.New(t)
	metrics := fakemetrics.New()

	nodeCache, err := nodecache.New(ctx, log, ds, clk, false, true)
	require.Nil(t, err)

	ef, err := NewAuthorizedEntryFetcherEvents(ctx, AuthorizedEntryFetcherEventsConfig{
		log:                     log,
		metrics:                 metrics,
		clk:                     clk,
		ds:                      ds,
		nodeCache:               nodeCache,
		cacheReloadInterval:     defaultCacheReloadInterval,
		fullCacheReloadInterval: defaultFullCacheReloadInterval,
		pruneEventsOlderThan:    defaultPruneEventsOlderThan,
		eventTimeout:            defaultEventTimeout,
	})
	require.NoError(t, err)
	require.NotNil(t, ef)

	agent1 := spiffeid.RequireFromString("spiffe://example.org/myagent1")
	agent2 := spiffeid.RequireFromString("spiffe://example.org/myagent2")

	// Ensure no entries are in there to start
	entries, err := ef.FetchAuthorizedEntries(ctx, agent2)
	require.NoError(t, err)
	require.Zero(t, entries)

	// Create node alias for agent 2
	alias, err := ds.CreateRegistrationEntry(ctx, &common.RegistrationEntry{
		SpiffeId: "spiffe://example.org/alias",
		ParentId: "spiffe://example.org/spire/server",
		Selectors: []*common.Selector{
			{
				Type:  "test",
				Value: "alias",
			},
		},
	})
	assert.NoError(t, err)

	// Create a registration entry parented to the alias
	entry, err := ds.CreateRegistrationEntry(ctx, &common.RegistrationEntry{
		SpiffeId: "spiffe://example.org/viaalias",
		ParentId: alias.SpiffeId,
		Selectors: []*common.Selector{
			{
				Type:  "workload",
				Value: "two",
			},
		},
	})
	assert.NoError(t, err)

	// Create both Attested Nodes
	_, err = ds.CreateAttestedNode(ctx, &common.AttestedNode{
		SpiffeId:     agent1.String(),
		CertNotAfter: time.Now().Add(5 * time.Hour).Unix(),
	})
	require.NoError(t, err)

	_, err = ds.CreateAttestedNode(ctx, &common.AttestedNode{
		SpiffeId:     agent2.String(),
		CertNotAfter: time.Now().Add(5 * time.Hour).Unix(),
	})
	require.NoError(t, err)

	// Create selectors for agent 2
	err = ds.SetNodeSelectors(ctx, agent2.String(), []*common.Selector{
		{
			Type:  "test",
			Value: "alias",
		},
		{
			Type:  "test",
			Value: "cluster2",
		},
	})
	assert.NoError(t, err)

	// Create selectors for agent 1
	err = ds.SetNodeSelectors(ctx, agent1.String(), []*common.Selector{
		{
			Type:  "test",
			Value: "cluster1",
		},
	})
	assert.NoError(t, err)

	// Delete the events for agent 2 for now and then add it back later to simulate out of order events
	err = ds.DeleteAttestedNodeEventForTesting(ctx, 2)
	require.NoError(t, err)
	err = ds.DeleteAttestedNodeEventForTesting(ctx, 3)
	require.NoError(t, err)

	// Should not be in cache yet
	err = ef.updateCache(ctx)
	require.NoError(t, err)

	entries, err = ef.FetchAuthorizedEntries(ctx, agent2)
	require.NoError(t, err)
	require.Len(t, entries, 0)

	// Do full reload
	err = ef.buildCache(ctx)
	require.NoError(t, err)

	// Make sure it gets processed and the initial entry is deleted
	entries, err = ef.FetchAuthorizedEntries(ctx, agent2)
	require.NoError(t, err)
	compareEntries(t, entries, entry)
}

// AgentsByIDCacheCount
func agentsByIDMetric(val float64) fakemetrics.MetricItem {
	return fakemetrics.MetricItem{
		Type:   fakemetrics.SetGaugeType,
		Key:    []string{telemetry.Node, telemetry.AgentsByIDCache, telemetry.Count},
		Val:    val,
		Labels: nil}
}

func agentsByIDExpiresAtMetric(val float64) fakemetrics.MetricItem {
	return fakemetrics.MetricItem{
		Type:   fakemetrics.SetGaugeType,
		Key:    []string{telemetry.Node, telemetry.AgentsByExpiresAtCache, telemetry.Count},
		Val:    val,
		Labels: nil,
	}
}

func nodeAliasesByEntryIDMetric(val float64) fakemetrics.MetricItem {
	return fakemetrics.MetricItem{
		Type:   fakemetrics.SetGaugeType,
		Key:    []string{telemetry.Entry, telemetry.NodeAliasesByEntryIDCache, telemetry.Count},
		Val:    val,
		Labels: nil,
	}
}

func nodeSkippedEventMetric(val float64) fakemetrics.MetricItem {
	return fakemetrics.MetricItem{
		Type:   fakemetrics.SetGaugeType,
		Key:    []string{telemetry.Node, telemetry.SkippedNodeEventIDs, telemetry.Count},
		Val:    val,
		Labels: nil,
	}
}

func nodeAliasesBySelectorMetric(val float64) fakemetrics.MetricItem {
	return fakemetrics.MetricItem{
		Type:   fakemetrics.SetGaugeType,
		Key:    []string{telemetry.Entry, telemetry.NodeAliasesBySelectorCache, telemetry.Count},
		Val:    val,
		Labels: nil,
	}
}

func entriesByEntryIDMetric(val float64) fakemetrics.MetricItem {
	return fakemetrics.MetricItem{
		Type:   fakemetrics.SetGaugeType,
		Key:    []string{telemetry.Entry, telemetry.EntriesByEntryIDCache, telemetry.Count},
		Val:    val,
		Labels: nil,
	}
}

func entriesByParentIDMetric(val float64) fakemetrics.MetricItem {
	return fakemetrics.MetricItem{
		Type:   fakemetrics.SetGaugeType,
		Key:    []string{telemetry.Entry, telemetry.EntriesByParentIDCache, telemetry.Count},
		Val:    val,
		Labels: nil,
	}
}

func entriesSkippedEventMetric(val float64) fakemetrics.MetricItem {
	return fakemetrics.MetricItem{
		Type:   fakemetrics.SetGaugeType,
		Key:    []string{telemetry.Entry, telemetry.SkippedEntryEventIDs, telemetry.Count},
		Val:    val,
		Labels: nil,
	}
}

func compareEntries(t *testing.T, authorizedEntries []api.ReadOnlyEntry, entries ...*common.RegistrationEntry) {
	t.Helper()

	require.Equal(t, len(authorizedEntries), len(entries))
	entryIDs := make([]string, 0, len(authorizedEntries))
	spiffeIDs := make([]string, 0, len(authorizedEntries))
	for _, entry := range authorizedEntries {
		entryIDs = append(entryIDs, entry.GetId())
		spiffeIDs = append(spiffeIDs, idutil.RequireIDProtoString(entry.GetSpiffeId()))
	}

	for _, entry := range entries {
		require.Contains(t, entryIDs, entry.EntryId)
		require.Contains(t, spiffeIDs, entry.SpiffeId)
	}
}
