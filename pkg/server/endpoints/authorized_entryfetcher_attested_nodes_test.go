package endpoints

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/server/authorizedentries"
	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/fakes/fakedatastore"
	"github.com/spiffe/spire/test/fakes/fakemetrics"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUpdateAttestedNodesCache(t *testing.T) {
	for _, tt := range []struct {
		name                            string
		errs                            []error
		expectedLastAttestedNodeEventID uint
		expectMetrics                   []fakemetrics.MetricItem
	}{
		{
			name:                            "Error Listing Attested Node Events",
			errs:                            []error{errors.New("listing attested node events")},
			expectedLastAttestedNodeEventID: uint(0),
			expectMetrics:                   nil,
		},
		{
			name:                            "Error Fetching Attested Node",
			errs:                            []error{nil, errors.New("fetching attested node")},
			expectedLastAttestedNodeEventID: uint(0),
			expectMetrics:                   nil,
		},
		{
			name:                            "Error Getting Node Selectors",
			errs:                            []error{nil, nil, errors.New("getting node selectors")},
			expectedLastAttestedNodeEventID: uint(0),
			expectMetrics:                   nil,
		},
		{
			name:                            "No Errors",
			expectedLastAttestedNodeEventID: uint(1),
			expectMetrics: []fakemetrics.MetricItem{
				{
					Type:   fakemetrics.SetGaugeType,
					Key:    []string{telemetry.Node, telemetry.AgentsByExpiresAtCache, telemetry.Count},
					Val:    1,
					Labels: nil,
				},
				{
					Type:   fakemetrics.SetGaugeType,
					Key:    []string{telemetry.Node, telemetry.AgentsByIDCache, telemetry.Count},
					Val:    1,
					Labels: nil,
				},
			},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			log, _ := test.NewNullLogger()
			clk := clock.NewMock(t)
			ds := fakedatastore.New(t)
			cache := authorizedentries.NewCache(clk)
			metrics := fakemetrics.New()

			attestedNodes, err := buildAttestedNodesCache(ctx, log, metrics, ds, clk, cache, defaultSQLTransactionTimeout)
			require.NoError(t, err)
			require.NotNil(t, attestedNodes)

			agentID, err := spiffeid.FromString("spiffe://example.org/myagent")
			require.NoError(t, err)

			_, err = ds.CreateAttestedNode(ctx, &common.AttestedNode{
				SpiffeId:     agentID.String(),
				CertNotAfter: time.Now().Add(5 * time.Hour).Unix(),
			})
			require.NoError(t, err)

			for _, err = range tt.errs {
				ds.AppendNextError(err)
			}

			err = attestedNodes.updateCache(ctx)
			if len(tt.errs) > 0 {
				assert.EqualError(t, err, tt.errs[len(tt.errs)-1].Error())
			} else {
				assert.NoError(t, err)
			}

			assert.Equal(t, tt.expectedLastAttestedNodeEventID, attestedNodes.lastEventID)

			if tt.expectMetrics != nil {
				assert.Subset(t, metrics.AllMetrics(), tt.expectMetrics)
			}
		})
	}
}

func TestAttestedNodesCacheMissedEventNotFound(t *testing.T) {
	ctx := context.Background()
	log, hook := test.NewNullLogger()
	log.SetLevel(logrus.DebugLevel)
	clk := clock.NewMock(t)
	ds := fakedatastore.New(t)
	cache := authorizedentries.NewCache(clk)
	metrics := fakemetrics.New()

	attestedNodes, err := buildAttestedNodesCache(ctx, log, metrics, ds, clk, cache, defaultSQLTransactionTimeout)
	require.NoError(t, err)
	require.NotNil(t, attestedNodes)

	attestedNodes.missedEvents[1] = clk.Now()
	attestedNodes.replayMissedEvents(ctx)
	require.Zero(t, hook.Entries)
}

func TestAttestedNodesSavesMissedStartupEvents(t *testing.T) {
	ctx := context.Background()
	log, hook := test.NewNullLogger()
	log.SetLevel(logrus.DebugLevel)
	clk := clock.NewMock(t)
	ds := fakedatastore.New(t)
	cache := authorizedentries.NewCache(clk)
	metrics := fakemetrics.New()

	err := ds.CreateAttestedNodeEventForTesting(ctx, &datastore.AttestedNodeEvent{
		EventID:  3,
		SpiffeID: "test",
	})
	require.NoError(t, err)

	attestedNodes, err := buildAttestedNodesCache(ctx, log, metrics, ds, clk, cache, defaultSQLTransactionTimeout)
	require.NoError(t, err)
	require.NotNil(t, attestedNodes)
	require.Equal(t, uint(3), attestedNodes.firstEventID)

	err = ds.CreateAttestedNodeEventForTesting(ctx, &datastore.AttestedNodeEvent{
		EventID:  2,
		SpiffeID: "test",
	})
	require.NoError(t, err)

	err = attestedNodes.missedStartupEvents(ctx)
	require.NoError(t, err)

	// Make sure no dupliate calls are made
	ds.AppendNextError(nil)
	ds.AppendNextError(errors.New("Duplicate call"))
	err = attestedNodes.missedStartupEvents(ctx)
	require.NoError(t, err)
	require.Equal(t, 0, len(hook.AllEntries()))
}
