package endpoints

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/server/authorizedentries"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/fakes/fakedatastore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUpdateAttestedNodesCache(t *testing.T) {
	ctx := context.Background()
	log, _ := test.NewNullLogger()
	clk := clock.NewMock(t)
	ds := fakedatastore.New(t)
	cache := authorizedentries.NewCache(clk)

	attestedNodes, err := buildAttestedNodesCache(ctx, log, ds, clk, cache)
	require.NoError(t, err)
	require.NotNil(t, attestedNodes)

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

			err = attestedNodes.updateCache(ctx)
			if len(tt.errs) > 0 {
				assert.EqualError(t, err, tt.errs[len(tt.errs)-1].Error())
			} else {
				assert.NoError(t, err)
			}

			assert.Equal(t, tt.expectedLastAttestedNodeEventID, attestedNodes.lastEventID)
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

	attestedNodes, err := buildAttestedNodesCache(ctx, log, ds, clk, cache)
	require.NoError(t, err)
	require.NotNil(t, attestedNodes)

	attestedNodes.missedEvents[1] = clk.Now()
	attestedNodes.replayMissedEvents(ctx)
	require.Equal(t, "Event not yet populated in database", hook.LastEntry().Message)
}
