package endpoints

import (
	"context"
	"errors"
	"sort"
	"strconv"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/pkg/server/authorizedentries"
	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/fakes/fakedatastore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewAuthorizedEntryFetcherWithEventsBasedCache(t *testing.T) {
	ctx := context.Background()
	log, _ := test.NewNullLogger()
	clk := clock.NewMock(t)
	ds := fakedatastore.New(t)

	ef, err := NewAuthorizedEntryFetcherWithEventsBasedCache(ctx, log, clk, ds, defaultCacheReloadInterval, defaultPruneEventsOlderThan, defaultSQLTransactionTimeout)
	assert.NoError(t, err)
	assert.NotNil(t, ef)

	agentID, err := spiffeid.FromString("spiffe://example.org/myagent")
	assert.NoError(t, err)

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
	_, err = ds.CreateRegistrationEntry(ctx, &common.RegistrationEntry{
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
	_, err = ds.CreateRegistrationEntry(ctx, &common.RegistrationEntry{
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
	assert.Equal(t, 2, len(entries))
}

func TestNewAuthorizedEntryFetcherWithEventsBasedCacheErrorBuildingCache(t *testing.T) {
	ctx := context.Background()
	log, _ := test.NewNullLogger()
	clk := clock.NewMock(t)
	ds := fakedatastore.New(t)

	buildErr := errors.New("build error")
	ds.SetNextError(buildErr)

	ef, err := NewAuthorizedEntryFetcherWithEventsBasedCache(ctx, log, clk, ds, defaultCacheReloadInterval, defaultPruneEventsOlderThan, defaultSQLTransactionTimeout)
	assert.Error(t, err)
	assert.Nil(t, ef)
}

func TestBuildRegistrationEntriesCache(t *testing.T) {
	ctx := context.Background()
	clk := clock.NewMock(t)
	ds := fakedatastore.New(t)

	agentID, err := spiffeid.FromString("spiffe://example.org/myagent")
	require.NoError(t, err)

	// Create registration entries
	numEntries := 10
	for i := 0; i < numEntries; i++ {
		_, err := ds.CreateRegistrationEntry(ctx, &common.RegistrationEntry{
			SpiffeId: "spiffe://example.org/workload" + strconv.Itoa(i),
			ParentId: agentID.String(),
			Selectors: []*common.Selector{
				{
					Type:  "workload",
					Value: "one",
				},
			},
		})
		require.NoError(t, err)
	}

	for _, tt := range []struct {
		name     string
		pageSize int32
		err      string
	}{
		{
			name:     "Page size of 0",
			pageSize: 0,
			err:      "cannot paginate with pagesize = 0",
		},
		{
			name:     "Page size of half the entries",
			pageSize: int32(numEntries / 2),
		},
		{
			name:     "Page size of all the entries",
			pageSize: int32(numEntries),
		},
		{
			name:     "Page size of all the entries + 1",
			pageSize: int32(numEntries + 1),
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			cache := authorizedentries.NewCache(clk)
			receivedFirstRegistrationEntryEvent, lastRegistrationEntryEventID, _, err := buildRegistrationEntriesCache(ctx, ds, clk, cache, tt.pageSize)
			if tt.err != "" {
				require.Equal(t, uint(0), lastRegistrationEntryEventID)
				require.ErrorContains(t, err, tt.err)
				return
			}

			require.NoError(t, err)
			require.True(t, receivedFirstRegistrationEntryEvent)

			entries := cache.GetAuthorizedEntries(agentID)
			require.Equal(t, numEntries, len(entries))

			spiffeIDs := make([]string, 0, numEntries)
			for _, entry := range entries {
				spiffeID, err := idutil.IDFromProto(entry.SpiffeId)
				require.NoError(t, err)
				spiffeIDs = append(spiffeIDs, spiffeID.String())
			}
			sort.Strings(spiffeIDs)

			for i, spiffeID := range spiffeIDs {
				require.Equal(t, "spiffe://example.org/workload"+strconv.Itoa(i), spiffeID)
			}
		})
	}
}

func TestBuildCacheSavesMissedEvents(t *testing.T) {
	ctx := context.Background()
	log, _ := test.NewNullLogger()
	clk := clock.NewMock(t)
	ds := fakedatastore.New(t)

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

	ef, err := NewAuthorizedEntryFetcherWithEventsBasedCache(ctx, log, clk, ds, defaultCacheReloadInterval, defaultPruneEventsOlderThan, defaultSQLTransactionTimeout)
	require.NoError(t, err)
	require.NotNil(t, ef)

	assert.Contains(t, ef.missedRegistrationEntryEvents, uint(2))
	assert.Equal(t, uint(3), ef.lastRegistrationEntryEventID)

	assert.Contains(t, ef.missedAttestedNodeEvents, uint(2))
	assert.Contains(t, ef.missedAttestedNodeEvents, uint(3))
	assert.Equal(t, uint(4), ef.lastAttestedNodeEventID)
}

func TestUpdateAttestedNodesCache(t *testing.T) {
	ctx := context.Background()
	log, _ := test.NewNullLogger()
	clk := clock.NewMock(t)
	ds := fakedatastore.New(t)

	ef, err := NewAuthorizedEntryFetcherWithEventsBasedCache(ctx, log, clk, ds, defaultCacheReloadInterval, defaultPruneEventsOlderThan, defaultSQLTransactionTimeout)
	require.NoError(t, err)
	require.NotNil(t, ef)

	agentID, err := spiffeid.FromString("spiffe://example.org/myagent")
	require.NoError(t, err)

	_, err = ds.CreateAttestedNode(ctx, &common.AttestedNode{
		SpiffeId:     agentID.String(),
		CertNotAfter: time.Now().Add(5 * time.Hour).Unix(),
	})
	require.NoError(t, err)

	for _, tt := range []struct {
		name                            string
		errs                            []error
		expectedLastAttestedNodeEventID uint
	}{
		{
			name:                            "Error Listing Attested Node Events",
			errs:                            []error{errors.New("listing attested node events")},
			expectedLastAttestedNodeEventID: uint(0),
		},
		{
			name:                            "Error Fetching Attested Node",
			errs:                            []error{nil, errors.New("fetching attested node")},
			expectedLastAttestedNodeEventID: uint(0),
		},
		{
			name:                            "Error Getting Node Selectors",
			errs:                            []error{nil, nil, errors.New("getting node selectors")},
			expectedLastAttestedNodeEventID: uint(0),
		},
		{
			name:                            "No Errors",
			expectedLastAttestedNodeEventID: uint(1),
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			for _, err = range tt.errs {
				ds.AppendNextError(err)
			}

			err = ef.updateAttestedNodesCache(ctx)
			if len(tt.errs) > 0 {
				assert.EqualError(t, err, tt.errs[len(tt.errs)-1].Error())
			} else {
				assert.NoError(t, err)
			}

			assert.Equal(t, tt.expectedLastAttestedNodeEventID, ef.lastAttestedNodeEventID)
		})
	}
}

func TestRunUpdateCacheTaskPrunesExpiredAgents(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	log, hook := test.NewNullLogger()
	log.SetLevel(logrus.DebugLevel)
	clk := clock.NewMock(t)
	ds := fakedatastore.New(t)

	ef, err := NewAuthorizedEntryFetcherWithEventsBasedCache(ctx, log, clk, ds, defaultCacheReloadInterval, defaultPruneEventsOlderThan, defaultSQLTransactionTimeout)
	require.NoError(t, err)
	require.NotNil(t, ef)

	agentID, err := spiffeid.FromString("spiffe://example.org/myagent")
	require.NoError(t, err)

	// Start Update Task
	updateCacheTaskErr := make(chan error)
	go func() {
		updateCacheTaskErr <- ef.RunUpdateCacheTask(ctx)
	}()
	clk.WaitForAfter(time.Second, "waiting for initial task pause")
	entries, err := ef.FetchAuthorizedEntries(ctx, agentID)
	assert.NoError(t, err)
	require.Zero(t, entries)

	// Create Attested Node and Registration Entry
	_, err = ds.CreateAttestedNode(ctx, &common.AttestedNode{
		SpiffeId:     agentID.String(),
		CertNotAfter: clk.Now().Add(6 * time.Second).Unix(),
	})
	assert.NoError(t, err)

	_, err = ds.CreateRegistrationEntry(ctx, &common.RegistrationEntry{
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
	clk.WaitForAfter(time.Second, "waiting for task to pause after creating entries")
	entries, err = ef.FetchAuthorizedEntries(ctx, agentID)
	assert.NoError(t, err)
	require.Equal(t, 1, len(entries))

	// Make sure nothing was pruned yet
	for _, entry := range hook.AllEntries() {
		require.NotEqual(t, "Pruned expired agents from entry cache", entry.Message)
	}

	// Bump clock so entry expires and is pruned
	clk.Add(defaultCacheReloadInterval)
	clk.WaitForAfter(time.Second, "waiting for task to pause after expiring agent")
	assert.Equal(t, 1, hook.LastEntry().Data["count"])
	assert.Equal(t, "Pruned expired agents from entry cache", hook.LastEntry().Message)

	// Stop the task
	cancel()
	err = <-updateCacheTaskErr
	require.ErrorIs(t, err, context.Canceled)
}

func TestUpdateRegistrationEntriesCacheMissedEvents(t *testing.T) {
	ctx := context.Background()
	log, _ := test.NewNullLogger()
	clk := clock.NewMock(t)
	ds := fakedatastore.New(t)

	ef, err := NewAuthorizedEntryFetcherWithEventsBasedCache(ctx, log, clk, ds, defaultCacheReloadInterval, defaultPruneEventsOlderThan, defaultSQLTransactionTimeout)
	require.NoError(t, err)
	require.NotNil(t, ef)

	agentID, err := spiffeid.FromString("spiffe://example.org/myagent")
	require.NoError(t, err)

	// Ensure no entries are in there to start
	entries, err := ef.FetchAuthorizedEntries(ctx, agentID)
	require.NoError(t, err)
	require.Zero(t, entries)

	// Create Initial Registration Entry
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
	require.NoError(t, err)

	// Ensure it gets added to cache
	err = ef.updateRegistrationEntriesCache(ctx)
	require.NoError(t, err)

	entries, err = ef.FetchAuthorizedEntries(ctx, agentID)
	require.NoError(t, err)
	require.Equal(t, 1, len(entries))

	// Delete initial registration entry
	_, err = ds.DeleteRegistrationEntry(ctx, entry.EntryId)
	require.NoError(t, err)

	// Delete the event for now and then add it back later to simulate out of order events
	err = ds.DeleteRegistrationEntryEventForTesting(ctx, 2)
	require.NoError(t, err)

	// Create Second entry
	_, err = ds.CreateRegistrationEntry(ctx, &common.RegistrationEntry{
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
	err = ef.updateRegistrationEntriesCache(ctx)
	require.NoError(t, err)

	entries, err = ef.FetchAuthorizedEntries(ctx, agentID)
	require.NoError(t, err)
	require.Equal(t, 2, len(entries))

	// Add back in deleted event
	err = ds.CreateRegistrationEntryEventForTesting(ctx, &datastore.RegistrationEntryEvent{
		EventID: 2,
		EntryID: entry.EntryId,
	})
	require.NoError(t, err)

	// Make sure it gets processed and the initial entry is deleted
	err = ef.updateRegistrationEntriesCache(ctx)
	require.NoError(t, err)

	entries, err = ef.FetchAuthorizedEntries(ctx, agentID)
	require.NoError(t, err)
	require.Equal(t, 1, len(entries))
}

func TestUpdateAttestedNodesCacheMissedEvents(t *testing.T) {
	ctx := context.Background()
	log, _ := test.NewNullLogger()
	clk := clock.NewMock(t)
	ds := fakedatastore.New(t)

	ef, err := NewAuthorizedEntryFetcherWithEventsBasedCache(ctx, log, clk, ds, defaultCacheReloadInterval, defaultPruneEventsOlderThan, defaultSQLTransactionTimeout)
	require.NoError(t, err)
	require.NotNil(t, ef)

	agent1, err := spiffeid.FromString("spiffe://example.org/myagent1")
	require.NoError(t, err)
	agent2, err := spiffeid.FromString("spiffe://example.org/myagent2")
	require.NoError(t, err)

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
	_, err = ds.CreateRegistrationEntry(ctx, &common.RegistrationEntry{
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
	err = ef.updateRegistrationEntriesCache(ctx)
	require.NoError(t, err)
	err = ef.updateAttestedNodesCache(ctx)
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
	err = ef.updateRegistrationEntriesCache(ctx)
	require.NoError(t, err)
	err = ef.updateAttestedNodesCache(ctx)
	require.NoError(t, err)

	entries, err = ef.FetchAuthorizedEntries(ctx, agent2)
	require.NoError(t, err)
	require.Equal(t, 1, len(entries))
}

func TestAttestedNodesCacheMissedEventNotFound(t *testing.T) {
	ctx := context.Background()
	log, hook := test.NewNullLogger()
	log.SetLevel(logrus.DebugLevel)
	clk := clock.NewMock(t)
	ds := fakedatastore.New(t)

	ef, err := NewAuthorizedEntryFetcherWithEventsBasedCache(ctx, log, clk, ds, defaultCacheReloadInterval, defaultPruneEventsOlderThan, defaultSQLTransactionTimeout)
	require.NoError(t, err)
	require.NotNil(t, ef)

	ef.missedAttestedNodeEvents[1] = clk.Now()
	ef.replayMissedAttestedNodeEvents(ctx)
	require.Equal(t, "Event not yet populated in database", hook.LastEntry().Message)
}

func TestRegistrationEntriesCacheMissedEventNotFound(t *testing.T) {
	ctx := context.Background()
	log, hook := test.NewNullLogger()
	log.SetLevel(logrus.DebugLevel)
	clk := clock.NewMock(t)
	ds := fakedatastore.New(t)

	ef, err := NewAuthorizedEntryFetcherWithEventsBasedCache(ctx, log, clk, ds, defaultCacheReloadInterval, defaultPruneEventsOlderThan, defaultSQLTransactionTimeout)
	require.NoError(t, err)
	require.NotNil(t, ef)

	ef.missedRegistrationEntryEvents[1] = clk.Now()
	ef.replayMissedRegistrationEntryEvents(ctx)
	require.Equal(t, "Event not yet populated in database", hook.LastEntry().Message)
}
