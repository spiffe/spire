package telemetry

import (
	"time"
)

// latencyHistogramBuckets are the upper bounds, in milliseconds, of the
// Prometheus latency histogram buckets. They match the duration buckets of the
// M3 sink.
var latencyHistogramBuckets = func() []float64 {
	var buckets []float64
	for _, d := range durationBuckets {
		if d > 0 {
			buckets = append(buckets, float64(d)/float64(time.Millisecond))
		}
	}
	return buckets
}()

func latencyHistogramsEnabled(c FileConfig) bool {
	return c.EnableLatencyHistograms != nil && *c.EnableLatencyHistograms
}

// isLatencySample returns true for samples that measure a duration in
// milliseconds, which SPIRE emits with a key ending in elapsed_time.
func isLatencySample(key []string) bool {
	return len(key) > 0 && key[len(key)-1] == ElapsedTime
}

// latencyHistogramKey is the key of the histogram recorded alongside a
// latency sample.
func latencyHistogramKey(key []string) []string {
	return append(append(make([]string, 0, len(key)+1), key...), Histogram)
}
