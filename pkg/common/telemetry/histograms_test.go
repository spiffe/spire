package telemetry

import (
	"testing"

	"github.com/hashicorp/hcl"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLatencyHistogramBucketsMatchM3(t *testing.T) {
	require.Len(t, latencyHistogramBuckets, len(durationBuckets)-1)
	assert.Equal(t, float64(10), latencyHistogramBuckets[0])
	assert.Equal(t, float64(30000), latencyHistogramBuckets[len(latencyHistogramBuckets)-1])
}

func TestLatencyHistogramsEnabled(t *testing.T) {
	enabled, disabled := true, false
	assert.False(t, latencyHistogramsEnabled(FileConfig{}))
	assert.False(t, latencyHistogramsEnabled(FileConfig{EnableLatencyHistograms: &disabled}))
	assert.True(t, latencyHistogramsEnabled(FileConfig{EnableLatencyHistograms: &enabled}))

	var c FileConfig
	require.NoError(t, hcl.Decode(&c, `EnableLatencyHistograms = true`))
	assert.True(t, latencyHistogramsEnabled(c))
	assert.Empty(t, c.UnusedKeyPositions)
}

func TestIsLatencySample(t *testing.T) {
	assert.True(t, isLatencySample([]string{"spire_agent", "rpc", "fetch", ElapsedTime}))
	assert.False(t, isLatencySample([]string{"spire_agent", "workload_api", "discovered_selectors"}))
	assert.False(t, isLatencySample(nil))
}

func TestLatencyHistogramKey(t *testing.T) {
	// Spare capacity, because sinks in a fanout share the sample's key.
	backing := [3]string{"rpc", ElapsedTime, ""}
	key := backing[:2]

	histogramKey := latencyHistogramKey(key)
	assert.Equal(t, []string{"rpc", ElapsedTime, Histogram}, histogramKey)
	assert.Empty(t, backing[2], "the key's backing array is not written")

	histogramKey[0] = "changed"
	assert.Equal(t, "rpc", key[0])
}
