package endpoints

import (
	"context"
	"errors"
	"maps"
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
	CachedAgentsByID        = []string{telemetry.Node, telemetry.AgentsByIDCache, telemetry.Count}
	CachedAgentsByExpiresAt = []string{telemetry.Node, telemetry.AgentsByExpiresAtCache, telemetry.Count}
	SkippedNodeEventID      = []string{telemetry.Node, telemetry.SkippedNodeEventIDs, telemetry.Count}
)

type expectedGauge struct {
	Key   []string
	Value int
}

func TestLoadCache(t *testing.T) {
	for _, tt := range []struct {
		name          string
		attestedNodes []*common.AttestedNode
		errors        []error

		expectedNodes             int
		expectedError             error
		expectedAuthorizedEntries []string
		expectedGauges            []expectedGauge
	}{
		{
			name: "initial load returns an error",
			errors: []error{
				errors.New("any error, doesn't matter"),
			},
			expectedError: errors.New("any error, doesn't matter"),
		},
		{
			name: "initial load loads nothing",
		},
		{
			name: "initial load loads one attested node",
			attestedNodes: []*common.AttestedNode{
				&common.AttestedNode{
					SpiffeId:     "spiffe://example.org/test_node_1",
					CertNotAfter: time.Now().Add(time.Duration(5) * time.Hour).Unix(),
				},
			},
			expectedAuthorizedEntries: []string{
				"spiffe://example.org/test_node_1",
			},
			expectedGauges: []expectedGauge{
				expectedGauge{Key: SkippedNodeEventID, Value: 0},
				expectedGauge{Key: CachedAgentsByID, Value: 1},
				expectedGauge{Key: CachedAgentsByExpiresAt, Value: 1},
			},
		},
		{
			name: "initial load loads five attested nodes",
			attestedNodes: []*common.AttestedNode{
				&common.AttestedNode{
					SpiffeId:     "spiffe://example.org/test_node_1",
					CertNotAfter: time.Now().Add(time.Duration(5) * time.Hour).Unix(),
				},
				&common.AttestedNode{
					SpiffeId:     "spiffe://example.org/test_node_2",
					CertNotAfter: time.Now().Add(time.Duration(5) * time.Hour).Unix(),
				},
				&common.AttestedNode{
					SpiffeId:     "spiffe://example.org/test_node_3",
					CertNotAfter: time.Now().Add(time.Duration(5) * time.Hour).Unix(),
				},
				&common.AttestedNode{
					SpiffeId:     "spiffe://example.org/test_node_4",
					CertNotAfter: time.Now().Add(time.Duration(5) * time.Hour).Unix(),
				},
				&common.AttestedNode{
					SpiffeId:     "spiffe://example.org/test_node_5",
					CertNotAfter: time.Now().Add(time.Duration(5) * time.Hour).Unix(),
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
			attestedNodes: []*common.AttestedNode{
				&common.AttestedNode{
					SpiffeId:     "spiffe://example.org/test_node_1",
					CertNotAfter: time.Now().Add(time.Duration(5) * time.Hour).Unix(),
				},
				&common.AttestedNode{
					SpiffeId:     "spiffe://example.org/test_node_2",
					CertNotAfter: time.Now().Add(time.Duration(-5) * time.Hour).Unix(),
				},
				&common.AttestedNode{
					SpiffeId:     "spiffe://example.org/test_node_3",
					CertNotAfter: time.Now().Add(time.Duration(5) * time.Hour).Unix(),
				},
				&common.AttestedNode{
					SpiffeId:     "spiffe://example.org/test_node_4",
					CertNotAfter: time.Now().Add(time.Duration(5) * time.Hour).Unix(),
				},
				&common.AttestedNode{
					SpiffeId:     "spiffe://example.org/test_node_5",
					CertNotAfter: time.Now().Add(time.Duration(5) * time.Hour).Unix(),
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
			attestedNodes: []*common.AttestedNode{
				&common.AttestedNode{
					SpiffeId:     "spiffe://example.org/test_node_1",
					CertNotAfter: time.Now().Add(time.Duration(-5) * time.Hour).Unix(),
				},
				&common.AttestedNode{
					SpiffeId:     "spiffe://example.org/test_node_2",
					CertNotAfter: time.Now().Add(time.Duration(-5) * time.Hour).Unix(),
				},
				&common.AttestedNode{
					SpiffeId:     "spiffe://example.org/test_node_3",
					CertNotAfter: time.Now().Add(time.Duration(-5) * time.Hour).Unix(),
				},
				&common.AttestedNode{
					SpiffeId:     "spiffe://example.org/test_node_4",
					CertNotAfter: time.Now().Add(time.Duration(-5) * time.Hour).Unix(),
				},
				&common.AttestedNode{
					SpiffeId:     "spiffe://example.org/test_node_5",
					CertNotAfter: time.Now().Add(time.Duration(-5) * time.Hour).Unix(),
				},
			},
			expectedAuthorizedEntries: []string{},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			log, hook := test.NewNullLogger()
			log.SetLevel(logrus.DebugLevel)
			clk := clock.NewMock(t)
			cache := authorizedentries.NewCache(clk)
			metrics := fakemetrics.New()

			ds := fakedatastore.New(t)
			// initialize the database
			for _, attestedNode := range tt.attestedNodes {
				ds.CreateAttestedNode(ctx, attestedNode)
			}
			// prune attested node entires, to test the load independently of the events
			// this can be removed once CreateAttestedNode no longer creates node events.
			ds.PruneAttestedNodesEvents(ctx, time.Duration(-5)*time.Hour)
			for _, err := range tt.errors {
				ds.AppendNextError(err)
			}

			cacheStats := cache.Stats()
			require.Equal(t, 0, cacheStats.AgentsByID, "cache must be empty to start")

			attestedNodes, err := buildAttestedNodesCache(ctx, log, metrics, ds, clk, cache, defaultCacheReloadInterval, defaultSQLTransactionTimeout)
			if tt.expectedError != nil {
				require.Error(t, err, tt.expectedError)
				return
			}

			require.NoError(t, err)

			cacheStats = attestedNodes.cache.Stats()
			require.Equal(t, len(tt.expectedAuthorizedEntries), cacheStats.AgentsByID, "wrong number of agents by ID")

			for _, expectedAuthorizedId := range tt.expectedAuthorizedEntries {
				attestedNodes.cache.RemoveAgent(expectedAuthorizedId)
			}

			cacheStats = attestedNodes.cache.Stats()
			require.Equal(t, 0, cacheStats.AgentsByID, "clearing all expected agent ids didn't clear ccache")

			var lastMetrics map[string]int = make(map[string]int)
			for _, metricItem := range metrics.AllMetrics() {
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

			require.Zero(t, hook.Entries)
		})
	}
}

func TestSearchBeforeFirstEvent(t *testing.T) {
}

func TestSelectedPolledEvents(t *testing.T) {
	for _, tt := range []struct {
		name            string
		polling         []uint
		events          []*datastore.AttestedNodeEvent
		expectedFetches []string
	}{
		// polling is based on the eventTracker, not on events in the database
		{
			name:   "nothing to poll, no action taken, no events",
			events: []*datastore.AttestedNodeEvent{},
		},
		{
			name: "nothing to poll, no action taken, one event",
			events: []*datastore.AttestedNodeEvent{
				&datastore.AttestedNodeEvent{
					EventID:  100,
					SpiffeID: "spiffe://example.org/test_node_1",
				},
			},
		},
		{
			name: "nothing to poll, no action taken, five events",
			events: []*datastore.AttestedNodeEvent{
				&datastore.AttestedNodeEvent{
					EventID:  101,
					SpiffeID: "spiffe://example.org/test_node_1",
				},
				&datastore.AttestedNodeEvent{
					EventID:  102,
					SpiffeID: "spiffe://example.org/test_node_2",
				},
				&datastore.AttestedNodeEvent{
					EventID:  103,
					SpiffeID: "spiffe://example.org/test_node_3",
				},
				&datastore.AttestedNodeEvent{
					EventID:  104,
					SpiffeID: "spiffe://example.org/test_node_4",
				},
				&datastore.AttestedNodeEvent{
					EventID:  105,
					SpiffeID: "spiffe://example.org/test_node_5",
				},
			},
		},
		{
			name:    "polling one item, not found",
			polling: []uint{103},
			events: []*datastore.AttestedNodeEvent{
				&datastore.AttestedNodeEvent{
					EventID:  101,
					SpiffeID: "spiffe://example.org/test_node_1",
				},
				&datastore.AttestedNodeEvent{
					EventID:  102,
					SpiffeID: "spiffe://example.org/test_node_2",
				},
				&datastore.AttestedNodeEvent{
					EventID:  104,
					SpiffeID: "spiffe://example.org/test_node_4",
				},
				&datastore.AttestedNodeEvent{
					EventID:  105,
					SpiffeID: "spiffe://example.org/test_node_5",
				},
			},
		},
		{
			name:    "polling five items, not found",
			polling: []uint{102, 103, 104, 105, 106},
			events: []*datastore.AttestedNodeEvent{
				&datastore.AttestedNodeEvent{
					EventID:  101,
					SpiffeID: "spiffe://example.org/test_node_1",
				},
				&datastore.AttestedNodeEvent{
					EventID:  107,
					SpiffeID: "spiffe://example.org/test_node_7",
				},
			},
		},
		{
			name:    "polling one item, found",
			polling: []uint{102},
			events: []*datastore.AttestedNodeEvent{
				&datastore.AttestedNodeEvent{
					EventID:  101,
					SpiffeID: "spiffe://example.org/test_node_1",
				},
				&datastore.AttestedNodeEvent{
					EventID:  102,
					SpiffeID: "spiffe://example.org/test_node_2",
				},
				&datastore.AttestedNodeEvent{
					EventID:  103,
					SpiffeID: "spiffe://example.org/test_node_3",
				},
			},
			expectedFetches: []string{
				"spiffe://example.org/test_node_2",
			},
		},
		{
			name:    "polling five items, two found",
			polling: []uint{102, 103, 104, 105, 106},
			events: []*datastore.AttestedNodeEvent{
				&datastore.AttestedNodeEvent{
					EventID:  101,
					SpiffeID: "spiffe://example.org/test_node_1",
				},
				&datastore.AttestedNodeEvent{
					EventID:  103,
					SpiffeID: "spiffe://example.org/test_node_3",
				},
				&datastore.AttestedNodeEvent{
					EventID:  106,
					SpiffeID: "spiffe://example.org/test_node_6",
				},
				&datastore.AttestedNodeEvent{
					EventID:  107,
					SpiffeID: "spiffe://example.org/test_node_7",
				},
			},
			expectedFetches: []string{
				"spiffe://example.org/test_node_3",
				"spiffe://example.org/test_node_6",
			},
		},
		{
			name:    "polling five items, five found",
			polling: []uint{102, 103, 104, 105, 106},
			events: []*datastore.AttestedNodeEvent{
				&datastore.AttestedNodeEvent{
					EventID:  101,
					SpiffeID: "spiffe://example.org/test_node_1",
				},
				&datastore.AttestedNodeEvent{
					EventID:  102,
					SpiffeID: "spiffe://example.org/test_node_2",
				},
				&datastore.AttestedNodeEvent{
					EventID:  103,
					SpiffeID: "spiffe://example.org/test_node_3",
				},
				&datastore.AttestedNodeEvent{
					EventID:  104,
					SpiffeID: "spiffe://example.org/test_node_4",
				},
				&datastore.AttestedNodeEvent{
					EventID:  105,
					SpiffeID: "spiffe://example.org/test_node_5",
				},
				&datastore.AttestedNodeEvent{
					EventID:  106,
					SpiffeID: "spiffe://example.org/test_node_6",
				},
				&datastore.AttestedNodeEvent{
					EventID:  107,
					SpiffeID: "spiffe://example.org/test_node_7",
				},
			},
			expectedFetches: []string{
				"spiffe://example.org/test_node_2",
				"spiffe://example.org/test_node_3",
				"spiffe://example.org/test_node_4",
				"spiffe://example.org/test_node_5",
				"spiffe://example.org/test_node_6",
			},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			log, hook := test.NewNullLogger()
			log.SetLevel(logrus.DebugLevel)
			clk := clock.NewMock(t)
			ds := fakedatastore.New(t)
			cache := authorizedentries.NewCache(clk)
			metrics := fakemetrics.New()

			attestedNodes, err := buildAttestedNodesCache(ctx, log, metrics, ds, clk, cache, defaultCacheReloadInterval, defaultSQLTransactionTimeout)
			require.NoError(t, err)

			// initialize the database
			for _, event := range tt.events {
				ds.CreateAttestedNodeEventForTesting(ctx, event)
			}
			// initialize the event tracker
			for _, event := range tt.polling {
				attestedNodes.eventTracker.StartTracking(event)
			}

			// poll the events
			attestedNodes.selectPolledEvents(ctx)

			require.ElementsMatch(t, tt.expectedFetches, slices.Collect(maps.Keys(attestedNodes.fetchNodes)))
			require.Zero(t, hook.Entries)
		})
	}
}

func TestScanForNewEvents(t *testing.T) {
}

func TestUpdateAttestedNodesCache(t *testing.T) {
}
