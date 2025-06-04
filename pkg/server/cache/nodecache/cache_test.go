package nodecache

import (
	"testing"
	"time"

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

	_, err := ds.CreateAttestedNode(t.Context(), firstAgent)
	require.NoError(t, err)
	_, err = ds.CreateAttestedNode(t.Context(), secondAgent)
	require.NoError(t, err)
	_, err = ds.CreateAttestedNode(t.Context(), expiredAgent)
	require.NoError(t, err)

	cache, err := New(t.Context(), ds, clk, true, true)
	require.NoError(t, err)

	cachedFirstAgent, firstAgentTime, err := cache.FetchAttestedNode(firstAgent.SpiffeId)
	require.NoError(t, err)
	spiretest.AssertProtoEqual(t, cachedFirstAgent, firstAgent)
	require.Equal(t, firstAgentTime, clk.Now())

	cachedSecondAgent, secondAgentTime, err := cache.FetchAttestedNode(secondAgent.SpiffeId)
	require.NoError(t, err)
	spiretest.AssertProtoEqual(t, cachedSecondAgent, secondAgent)
	require.Equal(t, secondAgentTime, clk.Now())

	cachedExpiredAgent, _, err := cache.FetchAttestedNode(expiredAgent.SpiffeId)
	require.NoError(t, err)
	require.Nil(t, cachedExpiredAgent)

	secondAgent.CertSerialNumber = "456789"
	_, err = ds.UpdateAttestedNode(t.Context(), secondAgent, nil)
	require.NoError(t, err)

	// Advance the clk by 1 second to see that the time returned for the cache node
	// will reflect the fact that it was refreshed.
	clk.Add(time.Second)

	refreshedSecondAgent, err := cache.RefreshAttestedNode(t.Context(), secondAgent.SpiffeId)
	require.NoError(t, err)
	require.NotNil(t, refreshedSecondAgent)
	spiretest.AssertProtoEqual(t, refreshedSecondAgent, secondAgent)

	cachedSecondAgent, secondAgentTimeAfterRefresh, err := cache.FetchAttestedNode(secondAgent.SpiffeId)
	require.NoError(t, err)
	spiretest.AssertProtoEqual(t, cachedSecondAgent, secondAgent)
	require.Greater(t, secondAgentTimeAfterRefresh, secondAgentTime)
	require.Equal(t, secondAgentTimeAfterRefresh, clk.Now())
}

func TestCacheDisabled(t *testing.T) {
	ds := fakedatastore.New(t)

	_, err := ds.CreateAttestedNode(t.Context(), firstAgent)
	require.NoError(t, err)
	_, err = ds.CreateAttestedNode(t.Context(), expiredAgent)
	require.NoError(t, err)

	cache, err := New(t.Context(), ds, clock.NewMock(t), true, false)
	require.NoError(t, err)

	cachedFirstAgent, _, err := cache.FetchAttestedNode(firstAgent.SpiffeId)
	require.Nil(t, cachedFirstAgent)
	require.NoError(t, err)

	refreshedFirstAgent, err := cache.RefreshAttestedNode(t.Context(), firstAgent.SpiffeId)
	require.NoError(t, err)
	require.NotNil(t, refreshedFirstAgent)
	spiretest.AssertProtoEqual(t, refreshedFirstAgent, firstAgent)
}

func TestCachePeriodicRebuild(t *testing.T) {
	ds := fakedatastore.New(t)
	clk := clock.NewMock(t)

	_, err := ds.CreateAttestedNode(t.Context(), firstAgent)
	require.NoError(t, err)

	cache, err := New(t.Context(), ds, clk, true, true)
	require.NoError(t, err)

	go cache.PeriodicRebuild(t.Context())

	cachedFirstAgent, _, err := cache.FetchAttestedNode(firstAgent.SpiffeId)
	require.NoError(t, err)
	require.NotNil(t, cachedFirstAgent)

	cachedSecondAgent, _, err := cache.FetchAttestedNode(secondAgent.SpiffeId)
	require.NoError(t, err)
	require.Nil(t, cachedSecondAgent)

	_, err = ds.CreateAttestedNode(t.Context(), secondAgent)
	cachedSecondAgent, _, err = cache.FetchAttestedNode(secondAgent.SpiffeId)
	require.NoError(t, err)
	require.Nil(t, cachedSecondAgent)

	clk.Add(rebuildInterval)
	clk.Add(rebuildInterval)

	cachedSecondAgent, _, err = cache.FetchAttestedNode(secondAgent.SpiffeId)
	require.NoError(t, err)
	require.NotNil(t, cachedSecondAgent)
}

func TestCacheWithoutPeriodicRebuild(t *testing.T) {
	ds := fakedatastore.New(t)
	clk := clock.NewMock(t)

	firstNode, err := ds.CreateAttestedNode(t.Context(), firstAgent)
	require.NoError(t, err)

	cache, err := New(t.Context(), ds, clk, false, true)
	require.NoError(t, err)

	cachedFirstAgent, _, err := cache.FetchAttestedNode(firstAgent.SpiffeId)
	require.NoError(t, err)
	require.Nil(t, cachedFirstAgent)

	cache.UpdateAttestedNode(firstNode)

	cachedFirstAgent, _, err = cache.FetchAttestedNode(firstAgent.SpiffeId)
	require.NoError(t, err)
	require.NotNil(t, cachedFirstAgent)

	cachedSecondAgent, _, err := cache.FetchAttestedNode(secondAgent.SpiffeId)
	require.NoError(t, err)
	require.Nil(t, cachedSecondAgent)

	secondNode, err := ds.CreateAttestedNode(t.Context(), secondAgent)

	cachedSecondAgent, _, err = cache.FetchAttestedNode(secondAgent.SpiffeId)
	require.NoError(t, err)
	require.Nil(t, cachedSecondAgent)

	cache.UpdateAttestedNode(secondNode)

	cachedSecondAgent, _, err = cache.FetchAttestedNode(secondAgent.SpiffeId)
	require.NoError(t, err)
	require.NotNil(t, cachedSecondAgent)
}
