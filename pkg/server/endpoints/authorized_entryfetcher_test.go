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

	ef, err := NewAuthorizedEntryFetcherWithEventsBasedCache(ctx, log, clk, ds, defaultCacheReloadInterval, defaultPruneEventsOlderThan)
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

	ef, err := NewAuthorizedEntryFetcherWithEventsBasedCache(ctx, log, clk, ds, defaultCacheReloadInterval, defaultPruneEventsOlderThan)
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
			lastRegistrationEntryEventID, err := buildRegistrationEntriesCache(ctx, ds, cache, tt.pageSize)
			if tt.err != "" {
				require.Equal(t, uint(0), lastRegistrationEntryEventID)
				require.ErrorContains(t, err, tt.err)
				return
			}

			require.NoError(t, err)

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

func TestUpdateAttestedNodesCache(t *testing.T) {
	ctx := context.Background()
	log, _ := test.NewNullLogger()
	clk := clock.NewMock(t)
	ds := fakedatastore.New(t)

	ef, err := NewAuthorizedEntryFetcherWithEventsBasedCache(ctx, log, clk, ds, defaultCacheReloadInterval, defaultPruneEventsOlderThan)
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

	ef, err := NewAuthorizedEntryFetcherWithEventsBasedCache(ctx, log, clk, ds, defaultCacheReloadInterval, defaultPruneEventsOlderThan)
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
