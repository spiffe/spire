package endpoints

import (
	"context"
	"errors"
	"maps"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"

	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/server/authorizedentries"
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

	// defaults used to set up a small initial load of attested nodes and events.
	defaultAttestedNodes = []*common.AttestedNode{
		{
			SpiffeId:     "spiffe://example.org/test_node_2",
			CertNotAfter: time.Now().Add(time.Duration(240) * time.Hour).Unix(),
		},
		{
			SpiffeId:     "spiffe://example.org/test_node_3",
			CertNotAfter: time.Now().Add(time.Duration(240) * time.Hour).Unix(),
		},
	}
	defaultNodeEventsStartingAt60 = []*datastore.AttestedNodeEvent{
		{
			EventID:  60,
			SpiffeID: "spiffe://example.org/test_node_2",
		},
		{
			EventID:  61,
			SpiffeID: "spiffe://example.org/test_node_3",
		},
	}
	defaultFirstNodeEvent = uint(60)
	defaultLastNodeEvent  = uint(61)

	noNodeFetches = []string{}
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

			var lastMetrics map[string]int = make(map[string]int)
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

func TestSearchBeforeFirstNodeEvent(t *testing.T) {
	for _, tt := range []struct {
		name  string
		setup *nodeScenarioSetup

		waitToPoll        time.Duration
		eventsBeforeFirst []uint
		polledEvents      []*datastore.AttestedNodeEvent
		errors            []error

		expectedError             string
		expectedEventsBeforeFirst []uint
		expectedFetches           []string
	}{
		{
			name: "first event not loaded",

			expectedEventsBeforeFirst: []uint{},
			expectedFetches:           []string{},
		},
		{
			name: "before first event arrived, after transaction timeout",
			setup: &nodeScenarioSetup{
				attestedNodes:      defaultAttestedNodes,
				attestedNodeEvents: defaultNodeEventsStartingAt60,
			},

			waitToPoll: time.Duration(2) * defaultSQLTransactionTimeout,
			// even with new before first events, they shouldn't load
			polledEvents: []*datastore.AttestedNodeEvent{
				{
					EventID:  58,
					SpiffeID: "spiffe://example.org/test_node_1",
				},
			},

			expectedEventsBeforeFirst: []uint{},
			expectedFetches:           noNodeFetches,
		},
		{
			name: "no before first events",

			setup: &nodeScenarioSetup{
				attestedNodes:      defaultAttestedNodes,
				attestedNodeEvents: defaultNodeEventsStartingAt60,
			},
			polledEvents: []*datastore.AttestedNodeEvent{},

			expectedEventsBeforeFirst: []uint{},
			expectedFetches:           []string{},
		},
		{
			name: "new before first event",

			setup: &nodeScenarioSetup{
				attestedNodes:      defaultAttestedNodes,
				attestedNodeEvents: defaultNodeEventsStartingAt60,
			},
			polledEvents: []*datastore.AttestedNodeEvent{
				{
					EventID:  58,
					SpiffeID: "spiffe://example.org/test_node_1",
				},
			},

			expectedEventsBeforeFirst: []uint{58},
			expectedFetches:           []string{"spiffe://example.org/test_node_1"},
		},
		{
			name: "new after last event",

			setup: &nodeScenarioSetup{
				attestedNodes:      defaultAttestedNodes,
				attestedNodeEvents: defaultNodeEventsStartingAt60,
			},
			polledEvents: []*datastore.AttestedNodeEvent{
				{
					EventID:  64,
					SpiffeID: "spiffe://example.org/test_node_1",
				},
			},

			expectedEventsBeforeFirst: []uint{},
			expectedFetches:           []string{},
		},
		{
			name: "previously seen before first event",

			setup: &nodeScenarioSetup{
				attestedNodes:      defaultAttestedNodes,
				attestedNodeEvents: defaultNodeEventsStartingAt60,
			},
			eventsBeforeFirst: []uint{58},
			polledEvents: []*datastore.AttestedNodeEvent{
				{
					EventID:  58,
					SpiffeID: "spiffe://example.org/test_node_1",
				},
			},

			expectedEventsBeforeFirst: []uint{58},
			expectedFetches:           []string{},
		},
		{
			name: "previously seen before first event and after last event",

			setup: &nodeScenarioSetup{
				attestedNodes:      defaultAttestedNodes,
				attestedNodeEvents: defaultNodeEventsStartingAt60,
			},
			eventsBeforeFirst: []uint{58},
			polledEvents: []*datastore.AttestedNodeEvent{
				{
					EventID:  defaultFirstNodeEvent - 2,
					SpiffeID: "spiffe://example.org/test_node_1",
				},
				{
					EventID:  defaultLastNodeEvent + 2,
					SpiffeID: "spiffe://example.org/test_node_4",
				},
			},

			expectedEventsBeforeFirst: []uint{defaultFirstNodeEvent - 2},
			expectedFetches:           []string{},
		},
		{
			name: "five new before first events",

			setup: &nodeScenarioSetup{
				attestedNodes:      defaultAttestedNodes,
				attestedNodeEvents: defaultNodeEventsStartingAt60,
			},
			polledEvents: []*datastore.AttestedNodeEvent{
				{
					EventID:  48,
					SpiffeID: "spiffe://example.org/test_node_10",
				},
				{
					EventID:  49,
					SpiffeID: "spiffe://example.org/test_node_11",
				},
				{
					EventID:  53,
					SpiffeID: "spiffe://example.org/test_node_12",
				},
				{
					EventID:  56,
					SpiffeID: "spiffe://example.org/test_node_13",
				},
				{
					EventID:  57,
					SpiffeID: "spiffe://example.org/test_node_14",
				},
			},

			expectedEventsBeforeFirst: []uint{48, 49, 53, 56, 57},
			expectedFetches: []string{
				"spiffe://example.org/test_node_10",
				"spiffe://example.org/test_node_11",
				"spiffe://example.org/test_node_12",
				"spiffe://example.org/test_node_13",
				"spiffe://example.org/test_node_14",
			},
		},
		{
			name: "five new before first events, one after last event",

			setup: &nodeScenarioSetup{
				attestedNodes:      defaultAttestedNodes,
				attestedNodeEvents: defaultNodeEventsStartingAt60,
			},
			polledEvents: []*datastore.AttestedNodeEvent{
				{
					EventID:  48,
					SpiffeID: "spiffe://example.org/test_node_10",
				},
				{
					EventID:  49,
					SpiffeID: "spiffe://example.org/test_node_11",
				},
				{
					EventID:  53,
					SpiffeID: "spiffe://example.org/test_node_12",
				},
				{
					EventID:  56,
					SpiffeID: "spiffe://example.org/test_node_13",
				},
				{
					EventID:  defaultLastNodeEvent + 1,
					SpiffeID: "spiffe://example.org/test_node_14",
				},
			},

			expectedEventsBeforeFirst: []uint{48, 49, 53, 56},
			expectedFetches: []string{
				"spiffe://example.org/test_node_10",
				"spiffe://example.org/test_node_11",
				"spiffe://example.org/test_node_12",
				"spiffe://example.org/test_node_13",
			},
		},
		{
			name: "five before first events, two previously seen",
			setup: &nodeScenarioSetup{
				attestedNodes:      defaultAttestedNodes,
				attestedNodeEvents: defaultNodeEventsStartingAt60,
			},

			eventsBeforeFirst: []uint{48, 49},
			polledEvents: []*datastore.AttestedNodeEvent{
				{
					EventID:  48,
					SpiffeID: "spiffe://example.org/test_node_10",
				},
				{
					EventID:  49,
					SpiffeID: "spiffe://example.org/test_node_11",
				},
				{
					EventID:  53,
					SpiffeID: "spiffe://example.org/test_node_12",
				},
				{
					EventID:  56,
					SpiffeID: "spiffe://example.org/test_node_13",
				},
				{
					EventID:  57,
					SpiffeID: "spiffe://example.org/test_node_14",
				},
			},

			expectedEventsBeforeFirst: []uint{48, 49, 53, 56, 57},
			expectedFetches: []string{
				"spiffe://example.org/test_node_12",
				"spiffe://example.org/test_node_13",
				"spiffe://example.org/test_node_14",
			},
		},
		{
			name: "five before first events, two previously seen, one after last event",
			setup: &nodeScenarioSetup{
				attestedNodes:      defaultAttestedNodes,
				attestedNodeEvents: defaultNodeEventsStartingAt60,
			},
			eventsBeforeFirst: []uint{48, 49},
			polledEvents: []*datastore.AttestedNodeEvent{
				{
					EventID:  48,
					SpiffeID: "spiffe://example.org/test_node_10",
				},
				{
					EventID:  49,
					SpiffeID: "spiffe://example.org/test_node_11",
				},
				{
					EventID:  53,
					SpiffeID: "spiffe://example.org/test_node_12",
				},
				{
					EventID:  56,
					SpiffeID: "spiffe://example.org/test_node_13",
				},
				{
					EventID:  defaultLastNodeEvent + 1,
					SpiffeID: "spiffe://example.org/test_node_14",
				},
			},

			expectedEventsBeforeFirst: []uint{48, 49, 53, 56},
			expectedFetches: []string{
				"spiffe://example.org/test_node_12",
				"spiffe://example.org/test_node_13",
			},
		},
		{
			name: "five before first events, five previously seen",
			setup: &nodeScenarioSetup{
				attestedNodes:      defaultAttestedNodes,
				attestedNodeEvents: defaultNodeEventsStartingAt60,
			},

			eventsBeforeFirst: []uint{48, 49, 53, 56, 57},
			polledEvents: []*datastore.AttestedNodeEvent{
				{
					EventID:  48,
					SpiffeID: "spiffe://example.org/test_node_10",
				},
				{
					EventID:  49,
					SpiffeID: "spiffe://example.org/test_node_11",
				},
				{
					EventID:  53,
					SpiffeID: "spiffe://example.org/test_node_12",
				},
				{
					EventID:  56,
					SpiffeID: "spiffe://example.org/test_node_13",
				},
				{
					EventID:  57,
					SpiffeID: "spiffe://example.org/test_node_14",
				},
			},

			expectedEventsBeforeFirst: []uint{48, 49, 53, 56, 57},
			expectedFetches:           []string{},
		},
		{
			name: "five before first events, five previously seen, with after last event",
			setup: &nodeScenarioSetup{
				attestedNodes:      defaultAttestedNodes,
				attestedNodeEvents: defaultNodeEventsStartingAt60,
			},

			eventsBeforeFirst: []uint{48, 49, 53, 56, 57},
			polledEvents: []*datastore.AttestedNodeEvent{
				{
					EventID:  48,
					SpiffeID: "spiffe://example.org/test_node_10",
				},
				{
					EventID:  49,
					SpiffeID: "spiffe://example.org/test_node_11",
				},
				{
					EventID:  53,
					SpiffeID: "spiffe://example.org/test_node_12",
				},
				{
					EventID:  56,
					SpiffeID: "spiffe://example.org/test_node_13",
				},
				{
					EventID:  57,
					SpiffeID: "spiffe://example.org/test_node_14",
				},
				{
					EventID:  defaultLastNodeEvent + 1,
					SpiffeID: "spiffe://example.org/test_node_28",
				},
			},

			expectedEventsBeforeFirst: []uint{48, 49, 53, 56, 57},
			expectedFetches:           []string{},
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

			if tt.waitToPoll == 0 {
				scenario.clk.Add(defaultCacheReloadInterval)
			} else {
				scenario.clk.Add(tt.waitToPoll)
			}

			for _, event := range tt.eventsBeforeFirst {
				attestedNodes.eventsBeforeFirst[event] = struct{}{}
			}

			for _, event := range tt.polledEvents {
				err = scenario.ds.CreateAttestedNodeEventForTesting(scenario.ctx, event)
				require.NoError(t, err, "error while setting up test")
			}

			err = attestedNodes.searchBeforeFirstEvent(scenario.ctx)
			require.NoError(t, err, "error while running test")

			t.Log(reflect.TypeOf(maps.Keys(attestedNodes.eventsBeforeFirst)))
			require.ElementsMatch(t, tt.expectedEventsBeforeFirst, slices.Collect(maps.Keys(attestedNodes.eventsBeforeFirst)), "expected events before tracking mismatch")
			require.ElementsMatch(t, tt.expectedEventsBeforeFirst, slices.Collect(maps.Keys(attestedNodes.eventsBeforeFirst)), "expected events before tracking mismatch")
			require.ElementsMatch(t, tt.expectedFetches, slices.Collect[string](maps.Keys(attestedNodes.fetchNodes)), "expected fetches mismatch")

			require.Zero(t, scenario.hook.Entries)
		})
	}
}

func TestSelectedPolledNodeEvents(t *testing.T) {
	for _, tt := range []struct {
		name  string
		setup *nodeScenarioSetup

		polling         []uint
		events          []*datastore.AttestedNodeEvent
		expectedFetches []string
	}{
		// polling is based on the eventTracker, not on events in the database
		{
			name:   "nothing after to poll, no action taken, no events",
			events: []*datastore.AttestedNodeEvent{},
		},
		{
			name: "nothing to poll, no action take, one event",
			setup: &nodeScenarioSetup{
				attestedNodeEvents: []*datastore.AttestedNodeEvent{
					{
						EventID:  100,
						SpiffeID: "spiffe://example.org/test_node_1",
					},
				},
			},
		},
		{
			name: "nothing to poll, no action taken, five events",
			setup: &nodeScenarioSetup{
				attestedNodeEvents: []*datastore.AttestedNodeEvent{
					{
						EventID:  101,
						SpiffeID: "spiffe://example.org/test_node_1",
					},
					{
						EventID:  102,
						SpiffeID: "spiffe://example.org/test_node_2",
					},
					{
						EventID:  103,
						SpiffeID: "spiffe://example.org/test_node_3",
					},
					{
						EventID:  104,
						SpiffeID: "spiffe://example.org/test_node_4",
					},
					{
						EventID:  105,
						SpiffeID: "spiffe://example.org/test_node_5",
					},
				},
			},
		},
		{
			name: "polling one item, not found",
			setup: &nodeScenarioSetup{
				attestedNodeEvents: []*datastore.AttestedNodeEvent{
					{
						EventID:  101,
						SpiffeID: "spiffe://example.org/test_node_1",
					},
					{
						EventID:  102,
						SpiffeID: "spiffe://example.org/test_node_2",
					},
					{
						EventID:  104,
						SpiffeID: "spiffe://example.org/test_node_4",
					},
					{
						EventID:  105,
						SpiffeID: "spiffe://example.org/test_node_5",
					},
				},
			},
			polling: []uint{103},
		},
		{
			name: "polling five items, not found",
			setup: &nodeScenarioSetup{
				attestedNodeEvents: []*datastore.AttestedNodeEvent{
					{
						EventID:  101,
						SpiffeID: "spiffe://example.org/test_node_1",
					},
					{
						EventID:  107,
						SpiffeID: "spiffe://example.org/test_node_7",
					},
				},
			},
			polling: []uint{102, 103, 104, 105, 106},
		},
		{
			name: "polling one item, found",
			setup: &nodeScenarioSetup{
				attestedNodeEvents: []*datastore.AttestedNodeEvent{
					{
						EventID:  101,
						SpiffeID: "spiffe://example.org/test_node_1",
					},
					{
						EventID:  102,
						SpiffeID: "spiffe://example.org/test_node_2",
					},
					{
						EventID:  103,
						SpiffeID: "spiffe://example.org/test_node_3",
					},
				},
			},
			polling: []uint{102},

			expectedFetches: []string{
				"spiffe://example.org/test_node_2",
			},
		},
		{
			name: "polling five items, two found",
			setup: &nodeScenarioSetup{
				attestedNodeEvents: []*datastore.AttestedNodeEvent{
					{
						EventID:  101,
						SpiffeID: "spiffe://example.org/test_node_1",
					},
					{
						EventID:  103,
						SpiffeID: "spiffe://example.org/test_node_3",
					},
					{
						EventID:  106,
						SpiffeID: "spiffe://example.org/test_node_6",
					},
					{
						EventID:  107,
						SpiffeID: "spiffe://example.org/test_node_7",
					},
				},
			},
			polling: []uint{102, 103, 104, 105, 106},

			expectedFetches: []string{
				"spiffe://example.org/test_node_3",
				"spiffe://example.org/test_node_6",
			},
		},
		{
			name: "polling five items, five found",
			setup: &nodeScenarioSetup{
				attestedNodeEvents: []*datastore.AttestedNodeEvent{
					{
						EventID:  101,
						SpiffeID: "spiffe://example.org/test_node_1",
					},
					{
						EventID:  102,
						SpiffeID: "spiffe://example.org/test_node_2",
					},
					{
						EventID:  103,
						SpiffeID: "spiffe://example.org/test_node_3",
					},
					{
						EventID:  104,
						SpiffeID: "spiffe://example.org/test_node_4",
					},
					{
						EventID:  105,
						SpiffeID: "spiffe://example.org/test_node_5",
					},
					{
						EventID:  106,
						SpiffeID: "spiffe://example.org/test_node_6",
					},
					{
						EventID:  107,
						SpiffeID: "spiffe://example.org/test_node_7",
					},
				},
			},
			polling: []uint{102, 103, 104, 105, 106},

			expectedFetches: []string{
				"spiffe://example.org/test_node_2",
				"spiffe://example.org/test_node_3",
				"spiffe://example.org/test_node_4",
				"spiffe://example.org/test_node_5",
				"spiffe://example.org/test_node_6",
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			scenario := NewNodeScenario(t, tt.setup)
			attestedNodes, err := scenario.buildAttestedNodesCache()
			require.NoError(t, err)

			// initialize the event tracker
			for _, event := range tt.polling {
				attestedNodes.eventTracker.StartTracking(event)
			}
			// poll the events
			attestedNodes.selectPolledEvents(scenario.ctx)

			require.ElementsMatch(t, tt.expectedFetches, slices.Collect(maps.Keys(attestedNodes.fetchNodes)))
			require.Zero(t, scenario.hook.Entries)
		})
	}
}

func TestScanForNewNodeEvents(t *testing.T) {
	for _, tt := range []struct {
		name  string
		setup *nodeScenarioSetup

		newEvents []*datastore.AttestedNodeEvent

		expectedTrackedEvents []uint
		expectedFetches       []string
	}{
		{
			name: "no new events, no first event",

			expectedTrackedEvents: []uint{},
			expectedFetches:       []string{},
		},
		{
			name: "no new event, with first event",
			setup: &nodeScenarioSetup{
				attestedNodeEvents: []*datastore.AttestedNodeEvent{
					{
						EventID:  101,
						SpiffeID: "spiffe://example.org/test_node_1",
					},
				},
			},

			expectedTrackedEvents: []uint{},
			expectedFetches:       []string{},
		},
		{
			name: "one new event",
			setup: &nodeScenarioSetup{
				attestedNodeEvents: []*datastore.AttestedNodeEvent{
					{
						EventID:  101,
						SpiffeID: "spiffe://example.org/test_node_1",
					},
				},
			},
			newEvents: []*datastore.AttestedNodeEvent{
				{
					EventID:  102,
					SpiffeID: "spiffe://example.org/test_node_1",
				},
			},

			expectedTrackedEvents: []uint{},
			expectedFetches: []string{
				"spiffe://example.org/test_node_1",
			},
		},
		{
			name: "one new event, skipping an event",
			setup: &nodeScenarioSetup{
				attestedNodeEvents: []*datastore.AttestedNodeEvent{
					{
						EventID:  101,
						SpiffeID: "spiffe://example.org/test_node_1",
					},
				},
			},
			newEvents: []*datastore.AttestedNodeEvent{
				{
					EventID:  103,
					SpiffeID: "spiffe://example.org/test_node_1",
				},
			},

			expectedTrackedEvents: []uint{102},
			expectedFetches: []string{
				"spiffe://example.org/test_node_1",
			},
		},
		{
			name: "two new events, same attested node",
			setup: &nodeScenarioSetup{
				attestedNodeEvents: []*datastore.AttestedNodeEvent{
					{
						EventID:  101,
						SpiffeID: "spiffe://example.org/test_node_1",
					},
				},
			},
			newEvents: []*datastore.AttestedNodeEvent{
				{
					EventID:  102,
					SpiffeID: "spiffe://example.org/test_node_1",
				},
				{
					EventID:  103,
					SpiffeID: "spiffe://example.org/test_node_1",
				},
			},

			expectedTrackedEvents: []uint{},
			expectedFetches: []string{
				"spiffe://example.org/test_node_1",
			},
		},
		{
			name: "two new events, different attested nodes",
			setup: &nodeScenarioSetup{
				attestedNodeEvents: []*datastore.AttestedNodeEvent{
					{
						EventID:  101,
						SpiffeID: "spiffe://example.org/test_node_1",
					},
				},
			},
			newEvents: []*datastore.AttestedNodeEvent{
				{
					EventID:  102,
					SpiffeID: "spiffe://example.org/test_node_1",
				},
				{
					EventID:  103,
					SpiffeID: "spiffe://example.org/test_node_2",
				},
			},

			expectedTrackedEvents: []uint{},
			expectedFetches: []string{
				"spiffe://example.org/test_node_1",
				"spiffe://example.org/test_node_2",
			},
		},
		{
			name: "two new events, with a skipped event",
			setup: &nodeScenarioSetup{
				attestedNodeEvents: []*datastore.AttestedNodeEvent{
					{
						EventID:  101,
						SpiffeID: "spiffe://example.org/test_node_1",
					},
				},
			},
			newEvents: []*datastore.AttestedNodeEvent{
				{
					EventID:  102,
					SpiffeID: "spiffe://example.org/test_node_1",
				},
				{
					EventID:  104,
					SpiffeID: "spiffe://example.org/test_node_2",
				},
			},

			expectedTrackedEvents: []uint{103},
			expectedFetches: []string{
				"spiffe://example.org/test_node_1",
				"spiffe://example.org/test_node_2",
			},
		},
		{
			name: "two new events, with three skipped events",
			setup: &nodeScenarioSetup{
				attestedNodeEvents: []*datastore.AttestedNodeEvent{
					{
						EventID:  101,
						SpiffeID: "spiffe://example.org/test_node_1",
					},
				},
			},
			newEvents: []*datastore.AttestedNodeEvent{
				{
					EventID:  102,
					SpiffeID: "spiffe://example.org/test_node_1",
				},
				{
					EventID:  106,
					SpiffeID: "spiffe://example.org/test_node_2",
				},
			},

			expectedTrackedEvents: []uint{103, 104, 105},
			expectedFetches: []string{
				"spiffe://example.org/test_node_1",
				"spiffe://example.org/test_node_2",
			},
		},
		{
			name: "five events, four new events, two skip regions",
			setup: &nodeScenarioSetup{
				attestedNodeEvents: []*datastore.AttestedNodeEvent{
					{
						EventID:  101,
						SpiffeID: "spiffe://example.org/test_node_1",
					},
					{
						EventID:  102,
						SpiffeID: "spiffe://example.org/test_node_2",
					},
					{
						EventID:  103,
						SpiffeID: "spiffe://example.org/test_node_3",
					},
					{
						EventID:  104,
						SpiffeID: "spiffe://example.org/test_node_4",
					},
					{
						EventID:  105,
						SpiffeID: "spiffe://example.org/test_node_5",
					},
				},
			},
			newEvents: []*datastore.AttestedNodeEvent{
				{
					EventID:  108,
					SpiffeID: "spiffe://example.org/test_node_1",
				},
				{
					EventID:  109,
					SpiffeID: "spiffe://example.org/test_node_2",
				},
				{
					EventID:  110,
					SpiffeID: "spiffe://example.org/test_node_2",
				},
				{
					EventID:  112,
					SpiffeID: "spiffe://example.org/test_node_11",
				},
			},

			expectedTrackedEvents: []uint{106, 107, 111},
			expectedFetches: []string{
				"spiffe://example.org/test_node_1",
				"spiffe://example.org/test_node_2",
				"spiffe://example.org/test_node_11",
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			scenario := NewNodeScenario(t, tt.setup)
			attestedNodes, err := scenario.buildAttestedNodesCache()
			require.NoError(t, err)

			for _, newEvent := range tt.newEvents {
				err = scenario.ds.CreateAttestedNodeEventForTesting(scenario.ctx, newEvent)
				require.NoError(t, err, "error while setting up test")
			}
			err = attestedNodes.scanForNewEvents(scenario.ctx)
			require.NoError(t, err, "error while running test")

			require.ElementsMatch(t, tt.expectedTrackedEvents, slices.Collect(maps.Keys(attestedNodes.eventTracker.events)))
			require.ElementsMatch(t, tt.expectedFetches, slices.Collect(maps.Keys(attestedNodes.fetchNodes)))
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
			err = scenario.ds.PruneAttestedNodeEvents(scenario.ctx, time.Duration(-5)*time.Hour)
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
	ctx     context.Context
	log     *logrus.Logger
	hook    *test.Hook
	clk     *clock.Mock
	cache   *authorizedentries.Cache
	metrics *fakemetrics.FakeMetrics
	ds      *fakedatastore.DataStore
}

type nodeScenarioSetup struct {
	attestedNodes      []*common.AttestedNode
	attestedNodeEvents []*datastore.AttestedNodeEvent
	err                error
}

func NewNodeScenario(t *testing.T, setup *nodeScenarioSetup) *scenario {
	t.Helper()
	ctx := context.Background()
	log, hook := test.NewNullLogger()
	log.SetLevel(logrus.DebugLevel)
	clk := clock.NewMock(t)
	cache := authorizedentries.NewCache(clk)
	metrics := fakemetrics.New()
	ds := fakedatastore.New(t)

	if setup == nil {
		setup = &nodeScenarioSetup{}
	}

	var err error
	// initialize the database
	for _, attestedNode := range setup.attestedNodes {
		_, err = ds.CreateAttestedNode(ctx, attestedNode)
		require.NoError(t, err, "error while setting up test")
	}
	// prune autocreated node events, to test the event logic in more scenarios
	// than possible with autocreated node events.
	err = ds.PruneAttestedNodeEvents(ctx, time.Duration(-5)*time.Hour)
	require.NoError(t, err, "error while setting up test")
	// and then add back the specified node events
	for _, event := range setup.attestedNodeEvents {
		err = ds.CreateAttestedNodeEventForTesting(ctx, event)
		require.NoError(t, err, "error while setting up test")
	}
	// inject db error for buildAttestedNodesCache call
	if setup.err != nil {
		ds.AppendNextError(setup.err)
	}

	return &scenario{
		ctx:     ctx,
		log:     log,
		hook:    hook,
		clk:     clk,
		cache:   cache,
		metrics: metrics,
		ds:      ds,
	}
}

func (s *scenario) buildAttestedNodesCache() (*attestedNodes, error) {
	attestedNodes, err := buildAttestedNodesCache(s.ctx, s.log, s.metrics, s.ds, s.clk, s.cache, defaultCacheReloadInterval, defaultSQLTransactionTimeout)
	if attestedNodes != nil {
		// clear out the fetches
		for node := range attestedNodes.fetchNodes {
			delete(attestedNodes.fetchNodes, node)
		}
	}
	return attestedNodes, err
}
