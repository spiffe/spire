package telemetry

import (
	"context"
	"testing"
	"time"

	prommetrics "github.com/armon/go-metrics/prometheus"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewPrometheusRunner(t *testing.T) {
	config := testConfig()
	pr, err := newTestPrometheusRunner(config)
	assert.Nil(t, err)
	assert.NotNil(t, pr)

	// It works when not configured
	config.FileConfig.Prometheus = nil
	pr, err = newTestPrometheusRunner(config)
	assert.Nil(t, err)
	assert.NotNil(t, pr)
}

func TestIsConfigured(t *testing.T) {
	config := testConfig()

	pr, err := newTestPrometheusRunner(config)
	require.NoError(t, err)
	assert.True(t, pr.isConfigured())

	config.FileConfig.Prometheus = nil
	pr, err = newTestPrometheusRunner(config)
	require.NoError(t, err)
	assert.False(t, pr.isConfigured())
}

func TestRun(t *testing.T) {
	config := testConfig()

	pr, err := newTestPrometheusRunner(config)
	require.NoError(t, err)

	errCh := make(chan error)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		errCh <- pr.run(ctx)
	}()

	// It stops when it's supposed to
	cancel()
	select {
	case err := <-errCh:
		assert.Equal(t, context.Canceled, err)
	case <-time.After(time.Minute):
		t.Fatal("timeout waiting for shutdown")
	}

	config.FileConfig.Prometheus = nil
	pr, err = newTestPrometheusRunner(config)
	require.NoError(t, err)

	go func() {
		errCh <- pr.run(context.Background())
	}()

	// It doesn't run if it's not configured
	select {
	case err := <-errCh:
		assert.Nil(t, err, "should be nil if not configured")
	case <-time.After(time.Minute):
		t.Fatal("prometheus running but not configured")
	}
}

func testConfig() *MetricsConfig {
	l, _ := test.NewNullLogger()

	return &MetricsConfig{
		Logger:      l,
		ServiceName: "foo",
		FileConfig: FileConfig{
			// Let prometheus listen on a random port
			Prometheus: &PrometheusConfig{},
		},
	}
}

// newTestPrometheusRunner wraps newPrometheusRunner, unregistering the
// collector after creation in order to avoid duplicate registration errors
func newTestPrometheusRunner(c *MetricsConfig) (sinkRunner, error) {
	runner, err := newPrometheusRunner(c)

	if runner != nil && runner.isConfigured() {
		pr := runner.(*prometheusRunner)
		sink := pr.sink.(*prommetrics.PrometheusSink)
		prometheus.Unregister(sink)
	}

	return runner, err
}
