package nodecache

import (
	"testing"
	"time"

	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/fakes/fakedatastore"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
)

var (
	firstAgent = &common.AttestedNode{
		SpiffeId:            "spiffe://example.org/agent-1",
		AttestationDataType: "example",
		CertSerialNumber:    "123456",
		CertNotAfter:        time.Now().Add(24 * time.Hour).Unix(),
	}
	secondAgent = &common.AttestedNode{
		SpiffeId:            "spiffe://example.org/agent-2",
		AttestationDataType: "example",
		CertSerialNumber:    "234567",
		CertNotAfter:        time.Now().Add(24 * time.Hour).Unix(),
	}
	expiredAgent = &common.AttestedNode{
		SpiffeId:            "spiffe://example.org/agent-expired",
		AttestationDataType: "example",
		CertSerialNumber:    "345678",
		CertNotAfter:        time.Now().Add(-time.Hour).Unix(),
	}
)

func TestCacheEnabled(t *testing.T) {
	ds := fakedatastore.New(t)
	clk := clock.NewMock(t)
	log, _ := test.NewNullLogger()

	_, err := ds.CreateAttestedNode(t.Context(), firstAgent)
	require.NoError(t, err)
	_, err = ds.CreateAttestedNode(t.Context(), secondAgent)
	require.NoError(t, err)
	_, err = ds.CreateAttestedNode(t.Context(), expiredAgent)
	require.NoError(t, err)

	cache, err := New(t.Context(), log, ds, clk, true, true)
	require.NoError(t, err)

	cachedFirstAgent, firstAgentTime := cache.LookupAttestedNode(firstAgent.SpiffeId)
	require.NoError(t, err)
	spiretest.AssertProtoEqual(t, cachedFirstAgent, firstAgent)
	require.Equal(t, firstAgentTime, clk.Now())

	cachedSecondAgent, secondAgentTime := cache.LookupAttestedNode(secondAgent.SpiffeId)
	require.NoError(t, err)
	spiretest.AssertProtoEqual(t, cachedSecondAgent, secondAgent)
	require.Equal(t, secondAgentTime, clk.Now())

	cachedExpiredAgent, _ := cache.LookupAttestedNode(expiredAgent.SpiffeId)
	require.NoError(t, err)
	require.Nil(t, cachedExpiredAgent)

	secondAgent.CertSerialNumber = "456789"
	_, err = ds.UpdateAttestedNode(t.Context(), secondAgent, nil)
	require.NoError(t, err)

	// Advance the clk by 1 second to see that the time returned for the cache node
	// will reflect the fact that it was refreshed.
	clk.Add(time.Second)

	refreshedSecondAgent, err := cache.FetchAttestedNode(t.Context(), secondAgent.SpiffeId)
	require.NoError(t, err)
	require.NotNil(t, refreshedSecondAgent)
	spiretest.AssertProtoEqual(t, refreshedSecondAgent, secondAgent)

	cachedSecondAgent, secondAgentTimeAfterRefresh := cache.LookupAttestedNode(secondAgent.SpiffeId)
	require.NoError(t, err)
	spiretest.AssertProtoEqual(t, cachedSecondAgent, secondAgent)
	require.Greater(t, secondAgentTimeAfterRefresh, secondAgentTime)
	require.Equal(t, secondAgentTimeAfterRefresh, clk.Now())
}

func TestCacheDisabled(t *testing.T) {
	ds := fakedatastore.New(t)
	log, _ := test.NewNullLogger()

	_, err := ds.CreateAttestedNode(t.Context(), firstAgent)
	require.NoError(t, err)
	_, err = ds.CreateAttestedNode(t.Context(), expiredAgent)
	require.NoError(t, err)

	cache, err := New(t.Context(), log, ds, clock.NewMock(t), true, false)
	require.NoError(t, err)

	cachedFirstAgent, _ := cache.LookupAttestedNode(firstAgent.SpiffeId)
	require.Nil(t, cachedFirstAgent)
	require.NoError(t, err)

	refreshedFirstAgent, err := cache.FetchAttestedNode(t.Context(), firstAgent.SpiffeId)
	require.NoError(t, err)
	require.NotNil(t, refreshedFirstAgent)
	spiretest.AssertProtoEqual(t, refreshedFirstAgent, firstAgent)
}

func TestCachePeriodicRebuild(t *testing.T) {
	ds := fakedatastore.New(t)
	clk := clock.NewMock(t)
	log, _ := test.NewNullLogger()

	_, err := ds.CreateAttestedNode(t.Context(), firstAgent)
	require.NoError(t, err)

	cache, err := New(t.Context(), log, ds, clk, true, true)
	require.NoError(t, err)

	go func() {
		err := cache.PeriodicRebuild(t.Context())
		require.NoError(t, err)
	}()

	cachedFirstAgent, _ := cache.LookupAttestedNode(firstAgent.SpiffeId)
	require.NoError(t, err)
	require.NotNil(t, cachedFirstAgent)

	cachedSecondAgent, _ := cache.LookupAttestedNode(secondAgent.SpiffeId)
	require.NoError(t, err)
	require.Nil(t, cachedSecondAgent)

	_, err = ds.CreateAttestedNode(t.Context(), secondAgent)
	require.NoError(t, err)

	cachedSecondAgent, _ = cache.LookupAttestedNode(secondAgent.SpiffeId)
	require.NoError(t, err)
	require.Nil(t, cachedSecondAgent)

	clk.Add(rebuildInterval)
	clk.Add(rebuildInterval)

	cachedSecondAgent, _ = cache.LookupAttestedNode(secondAgent.SpiffeId)
	require.NoError(t, err)
	require.NotNil(t, cachedSecondAgent)
}

func TestCacheWithoutPeriodicRebuild(t *testing.T) {
	ds := fakedatastore.New(t)
	clk := clock.NewMock(t)
	log, _ := test.NewNullLogger()

	firstNode, err := ds.CreateAttestedNode(t.Context(), firstAgent)
	require.NoError(t, err)

	cache, err := New(t.Context(), log, ds, clk, false, true)
	require.NoError(t, err)

	cachedFirstAgent, _ := cache.LookupAttestedNode(firstAgent.SpiffeId)
	require.NoError(t, err)
	require.Nil(t, cachedFirstAgent)

	cache.UpdateAttestedNode(firstNode)

	cachedFirstAgent, _ = cache.LookupAttestedNode(firstAgent.SpiffeId)
	require.NoError(t, err)
	require.NotNil(t, cachedFirstAgent)

	cachedSecondAgent, _ := cache.LookupAttestedNode(secondAgent.SpiffeId)
	require.NoError(t, err)
	require.Nil(t, cachedSecondAgent)

	secondNode, err := ds.CreateAttestedNode(t.Context(), secondAgent)
	require.NoError(t, err)

	cachedSecondAgent, _ = cache.LookupAttestedNode(secondAgent.SpiffeId)
	require.NoError(t, err)
	require.Nil(t, cachedSecondAgent)

	cache.UpdateAttestedNode(secondNode)

	cachedSecondAgent, _ = cache.LookupAttestedNode(secondAgent.SpiffeId)
	require.NoError(t, err)
	require.NotNil(t, cachedSecondAgent)
}
