package endpoints

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"

	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/server/authorizedentries"
	"github.com/spiffe/spire/pkg/server/cache/nodecache"
	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/fakes/fakedatastore"
	"github.com/spiffe/spire/test/fakes/fakemetrics"

	"github.com/stretchr/testify/require"
)

var (
	cachedAgentsByID        = []string{telemetry.Node, telemetry.AgentsByIDCache, telemetry.Count}
	cachedAgentsByExpiresAt = []string{telemetry.Node, telemetry.AgentsByExpiresAtCache, telemetry.Count}
	skippedNodeEventID      = []string{telemetry.Node, telemetry.SkippedNodeEventIDs, telemetry.Count}
)

type expectedGauge struct {
	Key   []string
	Value int
}

func TestLoadNodeCache(t *testing.T) {
	for _, tt := range []struct {
		name  string
		setup *nodeScenarioSetup

		expectedError             string
		expectedAuthorizedEntries []string
		expectedGauges            []expectedGauge
	}{
		{
			name: "initial load returns an error",
			setup: &nodeScenarioSetup{
				err: errors.New("any error, doesn't matter"),
			},
			expectedError: "any error, doesn't matter",
		},
		{
			name: "loading with a non-positive page size raises an error",
			setup: &nodeScenarioSetup{
				pageSize: -1,
			},
			expectedError: "page size must be positive, got -1",
		},
		{
			name: "initial load loads nothing",
		},
		{
			name: "initial load loads one attested node",
			setup: &nodeScenarioSetup{
				attestedNodes: []*common.AttestedNode{
					{
						SpiffeId:     "spiffe://example.org/test_node_1",
						CertNotAfter: time.Now().Add(time.Duration(5) * time.Hour).Unix(),
					},
				},
			},
			expectedAuthorizedEntries: []string{
				"spiffe://example.org/test_node_1",
			},
			expectedGauges: []expectedGauge{
				{Key: skippedNodeEventID, Value: 0},
				{Key: cachedAgentsByID, Value: 1},
				{Key: cachedAgentsByExpiresAt, Value: 1},
			},
		},
		{
			name: "initial load loads five attested nodes",
			setup: &nodeScenarioSetup{
				attestedNodes: []*common.AttestedNode{
					{
						SpiffeId:     "spiffe://example.org/test_node_1",
						CertNotAfter: time.Now().Add(time.Duration(5) * time.Hour).Unix(),
					},
					{
						SpiffeId:     "spiffe://example.org/test_node_2",
						CertNotAfter: time.Now().Add(time.Duration(5) * time.Hour).Unix(),
					},
					{
						SpiffeId:     "spiffe://example.org/test_node_3",
						CertNotAfter: time.Now().Add(time.Duration(5) * time.Hour).Unix(),
					},
					{
						SpiffeId:     "spiffe://example.org/test_node_4",
						CertNotAfter: time.Now().Add(time.Duration(5) * time.Hour).Unix(),
					},
					{
						SpiffeId:     "spiffe://example.org/test_node_5",
						CertNotAfter: time.Now().Add(time.Duration(5) * time.Hour).Unix(),
					},
				},
			},
			expectedAuthorizedEntries: []string{
				"spiffe://example.org/test_node_1",
				"spiffe://example.org/test_node_2",
				"spiffe://example.org/test_node_3",
				"spiffe://example.org/test_node_4",
				"spiffe://example.org/test_node_5",
			},
		},
		{
			name: "initial load loads five attested nodes, one expired",
			setup: &nodeScenarioSetup{
				attestedNodes: []*common.AttestedNode{
					{
						SpiffeId:     "spiffe://example.org/test_node_1",
						CertNotAfter: time.Now().Add(time.Duration(5) * time.Hour).Unix(),
					},
					{
						SpiffeId:     "spiffe://example.org/test_node_2",
						CertNotAfter: time.Now().Add(time.Duration(-5) * time.Hour).Unix(),
					},
					{
						SpiffeId:     "spiffe://example.org/test_node_3",
						CertNotAfter: time.Now().Add(time.Duration(5) * time.Hour).Unix(),
					},
					{
						SpiffeId:     "spiffe://example.org/test_node_4",
						CertNotAfter: time.Now().Add(time.Duration(5) * time.Hour).Unix(),
					},
					{
						SpiffeId:     "spiffe://example.org/test_node_5",
						CertNotAfter: time.Now().Add(time.Duration(5) * time.Hour).Unix(),
					},
				},
			},
			expectedAuthorizedEntries: []string{
				"spiffe://example.org/test_node_1",
				"spiffe://example.org/test_node_3",
				"spiffe://example.org/test_node_4",
				"spiffe://example.org/test_node_5",
			},
		},
		{
			name: "initial load loads five attested nodes, all expired",
			setup: &nodeScenarioSetup{
				attestedNodes: []*common.AttestedNode{
					{
						SpiffeId:     "spiffe://example.org/test_node_1",
						CertNotAfter: time.Now().Add(time.Duration(-5) * time.Hour).Unix(),
					},
					{
						SpiffeId:     "spiffe://example.org/test_node_2",
						CertNotAfter: time.Now().Add(time.Duration(-5) * time.Hour).Unix(),
					},
					{
						SpiffeId:     "spiffe://example.org/test_node_3",
						CertNotAfter: time.Now().Add(time.Duration(-5) * time.Hour).Unix(),
					},
					{
						SpiffeId:     "spiffe://example.org/test_node_4",
						CertNotAfter: time.Now().Add(time.Duration(-5) * time.Hour).Unix(),
					},
					{
						SpiffeId:     "spiffe://example.org/test_node_5",
						CertNotAfter: time.Now().Add(time.Duration(-5) * time.Hour).Unix(),
					},
				},
			},
			expectedAuthorizedEntries: []string{},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			scenario := NewNodeScenario(t, tt.setup)
			attestedNodes, err := scenario.buildAttestedNodesCache()
			if tt.expectedError != "" {
				require.ErrorContains(t, err, tt.expectedError)
				return
			}
			require.NoError(t, err)

			cacheStats := attestedNodes.cache.Stats()
			require.Equal(t, len(tt.expectedAuthorizedEntries), cacheStats.AgentsByID, "wrong number of agents by ID")

			// for now, the only way to ensure the desired agent ids are present is
			// to remove the desired ids and check the count is zero.
			for _, expectedAuthorizedId := range tt.expectedAuthorizedEntries {
				attestedNodes.cache.RemoveAgent(expectedAuthorizedId)
			}
			cacheStats = attestedNodes.cache.Stats()
			require.Equal(t, 0, cacheStats.AgentsByID, "clearing all expected agent ids didn't clear cache")

			lastMetrics := make(map[string]int)
			for _, metricItem := range scenario.metrics.AllMetrics() {
				if metricItem.Type == fakemetrics.SetGaugeType {
					key := strings.Join(metricItem.Key, " ")
					lastMetrics[key] = int(metricItem.Val)
				}
			}

			for _, expectedGauge := range tt.expectedGauges {
				key := strings.Join(expectedGauge.Key, " ")
				value, exists := lastMetrics[key]
				require.True(t, exists, "No metric value for %q", key)
				require.Equal(t, expectedGauge.Value, value, "unexpected final metric value for %q", key)
			}

			require.Zero(t, scenario.hook.Entries)
		})
	}
}

func TestUpdateAttestedNodesCache(t *testing.T) {
	for _, tt := range []struct {
		name                string
		setup               *nodeScenarioSetup
		createAttestedNodes []*common.AttestedNode // Nodes created after setup
		deleteAttestedNodes []string               // Nodes deleted after setup
		fetchNodes          []string

		expectedAuthorizedEntries []string
	}{
		{
			name:       "empty cache, no fetch nodes",
			fetchNodes: []string{},

			expectedAuthorizedEntries: []string{},
		},
		{
			name: "empty cache, fetch one node, as a new entry",
			createAttestedNodes: []*common.AttestedNode{
				{
					SpiffeId:     "spiffe://example.org/test_node_3",
					CertNotAfter: time.Now().Add(time.Duration(240) * time.Hour).Unix(),
				},
			},
			fetchNodes: []string{
				"spiffe://example.org/test_node_3",
			},

			expectedAuthorizedEntries: []string{
				"spiffe://example.org/test_node_3",
			},
		},
		{
			name: "empty cache, fetch one node, as a delete",
			fetchNodes: []string{
				"spiffe://example.org/test_node_3",
			},
		},
		{
			name: "empty cache, fetch five nodes, all new entries",
			createAttestedNodes: []*common.AttestedNode{
				{
					SpiffeId:     "spiffe://example.org/test_node_1",
					CertNotAfter: time.Now().Add(time.Duration(240) * time.Hour).Unix(),
				},
				{
					SpiffeId:     "spiffe://example.org/test_node_2",
					CertNotAfter: time.Now().Add(time.Duration(240) * time.Hour).Unix(),
				},
				{
					SpiffeId:     "spiffe://example.org/test_node_3",
					CertNotAfter: time.Now().Add(time.Duration(240) * time.Hour).Unix(),
				},
				{
					SpiffeId:     "spiffe://example.org/test_node_4",
					CertNotAfter: time.Now().Add(time.Duration(240) * time.Hour).Unix(),
				},
				{
					SpiffeId:     "spiffe://example.org/test_node_5",
					CertNotAfter: time.Now().Add(time.Duration(240) * time.Hour).Unix(),
				},
			},
			fetchNodes: []string{
				"spiffe://example.org/test_node_1",
				"spiffe://example.org/test_node_2",
				"spiffe://example.org/test_node_3",
				"spiffe://example.org/test_node_4",
				"spiffe://example.org/test_node_5",
			},

			expectedAuthorizedEntries: []string{
				"spiffe://example.org/test_node_1",
				"spiffe://example.org/test_node_2",
				"spiffe://example.org/test_node_3",
				"spiffe://example.org/test_node_4",
				"spiffe://example.org/test_node_5",
			},
		},
		{
			name: "empty cache, fetch five nodes, three new and two deletes",
			createAttestedNodes: []*common.AttestedNode{
				{
					SpiffeId:     "spiffe://example.org/test_node_1",
					CertNotAfter: time.Now().Add(time.Duration(240) * time.Hour).Unix(),
				},
				{
					SpiffeId:     "spiffe://example.org/test_node_3",
					CertNotAfter: time.Now().Add(time.Duration(240) * time.Hour).Unix(),
				},
				{
					SpiffeId:     "spiffe://example.org/test_node_4",
					CertNotAfter: time.Now().Add(time.Duration(240) * time.Hour).Unix(),
				},
			},
			fetchNodes: []string{
				"spiffe://example.org/test_node_1",
				"spiffe://example.org/test_node_2",
				"spiffe://example.org/test_node_3",
				"spiffe://example.org/test_node_4",
				"spiffe://example.org/test_node_5",
			},

			expectedAuthorizedEntries: []string{
				"spiffe://example.org/test_node_1",
				"spiffe://example.org/test_node_3",
				"spiffe://example.org/test_node_4",
			},
		},
		{
			name: "empty cache, fetch five nodes, all deletes",
			fetchNodes: []string{
				"spiffe://example.org/test_node_1",
				"spiffe://example.org/test_node_2",
				"spiffe://example.org/test_node_3",
				"spiffe://example.org/test_node_4",
				"spiffe://example.org/test_node_5",
			},

			expectedAuthorizedEntries: []string{},
		},
		{
			name: "one node in cache, no fetch nodes",
			setup: &nodeScenarioSetup{
				attestedNodes: []*common.AttestedNode{
					{
						SpiffeId:     "spiffe://example.org/test_node_3",
						CertNotAfter: time.Now().Add(time.Duration(240) * time.Hour).Unix(),
					},
				},
			},

			expectedAuthorizedEntries: []string{
				"spiffe://example.org/test_node_3",
			},
		},
		{
			name: "one node in cache, fetch one node, as new entry",
			setup: &nodeScenarioSetup{
				attestedNodes: []*common.AttestedNode{
					{
						SpiffeId:     "spiffe://example.org/test_node_3",
						CertNotAfter: time.Now().Add(time.Duration(240) * time.Hour).Unix(),
					},
				},
			},
			createAttestedNodes: []*common.AttestedNode{
				{
					SpiffeId:     "spiffe://example.org/test_node_4",
					CertNotAfter: time.Now().Add(time.Duration(240) * time.Hour).Unix(),
				},
			},
			fetchNodes: []string{
				"spiffe://example.org/test_node_4",
			},

			expectedAuthorizedEntries: []string{
				"spiffe://example.org/test_node_3",
				"spiffe://example.org/test_node_4",
			},
		},
		{
			name: "one node in cache, fetch one node, as an update",
			setup: &nodeScenarioSetup{
				attestedNodes: []*common.AttestedNode{
					{
						SpiffeId:     "spiffe://example.org/test_node_3",
						CertNotAfter: time.Now().Add(time.Duration(240) * time.Hour).Unix(),
					},
				},
			},
			fetchNodes: []string{
				"spiffe://example.org/test_node_3",
			},

			expectedAuthorizedEntries: []string{
				"spiffe://example.org/test_node_3",
			},
		},
		{
			name: "one node in cache, fetch one node, as a delete",
			setup: &nodeScenarioSetup{
				attestedNodes: []*common.AttestedNode{
					{
						SpiffeId:     "spiffe://example.org/test_node_3",
						CertNotAfter: time.Now().Add(time.Duration(240) * time.Hour).Unix(),
					},
				},
			},
			deleteAttestedNodes: []string{
				"spiffe://example.org/test_node_3",
			},
			fetchNodes: []string{
				"spiffe://example.org/test_node_3",
			},

			expectedAuthorizedEntries: []string{},
		},
		{
			name: "one node in cache, fetch five nodes, all new entries",
			setup: &nodeScenarioSetup{
				attestedNodes: []*common.AttestedNode{
					{
						SpiffeId:     "spiffe://example.org/test_node_3",
						CertNotAfter: time.Now().Add(time.Duration(240) * time.Hour).Unix(),
					},
				},
			},
			createAttestedNodes: []*common.AttestedNode{
				{
					SpiffeId:     "spiffe://example.org/test_node_1",
					CertNotAfter: time.Now().Add(time.Duration(240) * time.Hour).Unix(),
				},
				{
					SpiffeId:     "spiffe://example.org/test_node_2",
					CertNotAfter: time.Now().Add(time.Duration(240) * time.Hour).Unix(),
				},
				{
					SpiffeId:     "spiffe://example.org/test_node_4",
					CertNotAfter: time.Now().Add(time.Duration(240) * time.Hour).Unix(),
				},
				{
					SpiffeId:     "spiffe://example.org/test_node_5",
					CertNotAfter: time.Now().Add(time.Duration(240) * time.Hour).Unix(),
				},
				{
					SpiffeId:     "spiffe://example.org/test_node_6",
					CertNotAfter: time.Now().Add(time.Duration(240) * time.Hour).Unix(),
				},
			},
			fetchNodes: []string{
				"spiffe://example.org/test_node_1",
				"spiffe://example.org/test_node_2",
				"spiffe://example.org/test_node_4",
				"spiffe://example.org/test_node_5",
				"spiffe://example.org/test_node_6",
			},

			expectedAuthorizedEntries: []string{
				"spiffe://example.org/test_node_1",
				"spiffe://example.org/test_node_2",
				"spiffe://example.org/test_node_3",
				"spiffe://example.org/test_node_4",
				"spiffe://example.org/test_node_5",
				"spiffe://example.org/test_node_6",
			},
		},
		{
			name: "one node in cache, fetch five nodes, four new entries and one update",
			setup: &nodeScenarioSetup{
				attestedNodes: []*common.AttestedNode{
					{
						SpiffeId:     "spiffe://example.org/test_node_3",
						CertNotAfter: time.Now().Add(time.Duration(240) * time.Hour).Unix(),
					},
				},
			},
			createAttestedNodes: []*common.AttestedNode{
				{
					SpiffeId:     "spiffe://example.org/test_node_1",
					CertNotAfter: time.Now().Add(time.Duration(240) * time.Hour).Unix(),
				},
				{
					SpiffeId:     "spiffe://example.org/test_node_2",
					CertNotAfter: time.Now().Add(time.Duration(240) * time.Hour).Unix(),
				},
				{
					SpiffeId:     "spiffe://example.org/test_node_4",
					CertNotAfter: time.Now().Add(time.Duration(240) * time.Hour).Unix(),
				},
				{
					SpiffeId:     "spiffe://example.org/test_node_5",
					CertNotAfter: time.Now().Add(time.Duration(240) * time.Hour).Unix(),
				},
			},
			fetchNodes: []string{
				"spiffe://example.org/test_node_1",
				"spiffe://example.org/test_node_2",
				"spiffe://example.org/test_node_3",
				"spiffe://example.org/test_node_4",
				"spiffe://example.org/test_node_5",
			},

			expectedAuthorizedEntries: []string{
				"spiffe://example.org/test_node_1",
				"spiffe://example.org/test_node_2",
				"spiffe://example.org/test_node_3",
				"spiffe://example.org/test_node_4",
				"spiffe://example.org/test_node_5",
			},
		},
		{
			name: "one node in cache, fetch five nodes, two new and three deletes",
			setup: &nodeScenarioSetup{
				attestedNodes: []*common.AttestedNode{
					{
						SpiffeId:     "spiffe://example.org/test_node_3",
						CertNotAfter: time.Now().Add(time.Duration(240) * time.Hour).Unix(),
					},
				},
			},
			createAttestedNodes: []*common.AttestedNode{
				{
					SpiffeId:     "spiffe://example.org/test_node_1",
					CertNotAfter: time.Now().Add(time.Duration(240) * time.Hour).Unix(),
				},
				{
					SpiffeId:     "spiffe://example.org/test_node_2",
					CertNotAfter: time.Now().Add(time.Duration(240) * time.Hour).Unix(),
				},
			},
			deleteAttestedNodes: []string{
				"spiffe://example.org/test_node_3",
			},
			fetchNodes: []string{
				"spiffe://example.org/test_node_1",
				"spiffe://example.org/test_node_2",
				"spiffe://example.org/test_node_3",
				"spiffe://example.org/test_node_4",
				"spiffe://example.org/test_node_5",
			},

			expectedAuthorizedEntries: []string{
				"spiffe://example.org/test_node_1",
				"spiffe://example.org/test_node_2",
			},
		},
		{
			name: "one node in cache, fetch five nodes, all deletes",
			setup: &nodeScenarioSetup{
				attestedNodes: []*common.AttestedNode{
					{
						SpiffeId:     "spiffe://example.org/test_node_3",
						CertNotAfter: time.Now().Add(time.Duration(240) * time.Hour).Unix(),
					},
				},
			},
			deleteAttestedNodes: []string{
				"spiffe://example.org/test_node_3",
			},
			fetchNodes: []string{
				"spiffe://example.org/test_node_1",
				"spiffe://example.org/test_node_2",
				"spiffe://example.org/test_node_3",
				"spiffe://example.org/test_node_4",
				"spiffe://example.org/test_node_5",
			},

			expectedAuthorizedEntries: []string{},
		},
		{
			name: "empty cache, fetch five nodes spanning multiple pages, three new and two deletes",
			setup: &nodeScenarioSetup{
				pageSize: 2,
			},
			createAttestedNodes: []*common.AttestedNode{
				{
					SpiffeId:     "spiffe://example.org/test_node_1",
					CertNotAfter: time.Now().Add(time.Duration(240) * time.Hour).Unix(),
				},
				{
					SpiffeId:     "spiffe://example.org/test_node_3",
					CertNotAfter: time.Now().Add(time.Duration(240) * time.Hour).Unix(),
				},
				{
					SpiffeId:     "spiffe://example.org/test_node_5",
					CertNotAfter: time.Now().Add(time.Duration(240) * time.Hour).Unix(),
				},
			},
			fetchNodes: []string{
				"spiffe://example.org/test_node_1",
				"spiffe://example.org/test_node_2",
				"spiffe://example.org/test_node_3",
				"spiffe://example.org/test_node_4",
				"spiffe://example.org/test_node_5",
			},

			expectedAuthorizedEntries: []string{
				"spiffe://example.org/test_node_1",
				"spiffe://example.org/test_node_3",
				"spiffe://example.org/test_node_5",
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			scenario := NewNodeScenario(t, tt.setup)
			attestedNodes, err := scenario.buildAttestedNodesCache()
			require.NoError(t, err)

			for _, attestedNode := range tt.createAttestedNodes {
				_, err = scenario.ds.CreateAttestedNode(scenario.ctx, attestedNode)
				require.NoError(t, err, "error while setting up test")
			}
			for _, attestedNode := range tt.deleteAttestedNodes {
				_, err = scenario.ds.DeleteAttestedNode(scenario.ctx, attestedNode)
				require.NoError(t, err, "error while setting up test")
			}
			for _, fetchNode := range tt.fetchNodes {
				attestedNodes.fetchNodes[fetchNode] = struct{}{}
			}
			// clear out the events, to prove updates are not event based
			err = scenario.ds.PruneEvents(scenario.ctx, &datastore.PruneEventsRequest{OlderThan: -5 * time.Hour})
			require.NoError(t, err, "error while setting up test")

			err = attestedNodes.updateCachedNodes(scenario.ctx)
			require.NoError(t, err)

			cacheStats := attestedNodes.cache.Stats()
			require.Equal(t, len(tt.expectedAuthorizedEntries), cacheStats.AgentsByID, "wrong number of agents by ID")

			// for now, the only way to ensure the desired agent ids are present is
			// to remove the desired ids and check that the count is zero.
			for _, expectedAuthorizedId := range tt.expectedAuthorizedEntries {
				attestedNodes.cache.RemoveAgent(expectedAuthorizedId)
			}
			cacheStats = attestedNodes.cache.Stats()
			require.Equal(t, 0, cacheStats.AgentsByID, "clearing all expected agent ids didn't clear cache")
		})
	}
}

// utility functions
type scenario struct {
	ctx      context.Context
	log      *logrus.Logger
	hook     *test.Hook
	clk      *clock.Mock
	cache    *authorizedentries.Cache
	metrics  *fakemetrics.FakeMetrics
	ds       *fakedatastore.DataStore
	pageSize int32
}

type nodeScenarioSetup struct {
	attestedNodes []*common.AttestedNode
	err           error
	pageSize      int32
}

func NewNodeScenario(t *testing.T, setup *nodeScenarioSetup) *scenario {
	t.Helper()
	ctx := context.Background()
	log, hook := test.NewNullLogger()
	log.SetLevel(logrus.DebugLevel)
	clk := clock.NewMock(t)
	cache := authorizedentries.NewCache(clk, "example.org")
	metrics := fakemetrics.New()
	ds := fakedatastore.New(t)

	if setup == nil {
		setup = &nodeScenarioSetup{}
	}
	pageSize := setup.pageSize
	if pageSize == 0 {
		pageSize = 1024
	}

	var err error
	// initialize the database
	for _, attestedNode := range setup.attestedNodes {
		_, err = ds.CreateAttestedNode(ctx, attestedNode)
		require.NoError(t, err, "error while setting up test")
	}
	// The cache hydration tests populate refresh queues directly, so discard
	// events produced while setting up entities.
	err = ds.PruneEvents(ctx, &datastore.PruneEventsRequest{OlderThan: -5 * time.Hour})
	require.NoError(t, err, "error while setting up test")
	// inject db error for buildAttestedNodesCache call
	if setup.err != nil {
		ds.AppendNextError(setup.err)
	}

	return &scenario{
		ctx:      ctx,
		log:      log,
		hook:     hook,
		clk:      clk,
		cache:    cache,
		metrics:  metrics,
		ds:       ds,
		pageSize: pageSize,
	}
}

func (s *scenario) buildAttestedNodesCache() (*attestedNodes, error) {
	nodeCache, err := nodecache.New(s.ctx, s.log, s.ds, s.clk, false, true)
	if err != nil {
		return nil, err
	}

	attestedNodes, err := buildAttestedNodesCache(s.ctx, s.log, s.metrics, s.ds, s.clk, s.cache, nodeCache, s.pageSize, defaultEventTimeout)
	if attestedNodes != nil {
		// clear out the fetches
		for node := range attestedNodes.fetchNodes {
			delete(attestedNodes.fetchNodes, node)
		}
	}
	return attestedNodes, err
}
