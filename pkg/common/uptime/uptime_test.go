package uptime

import (
	"context"
	"testing"
	"time"

	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/fakes/fakemetrics"
	"github.com/stretchr/testify/assert"
)

func TestReportMetrics(t *testing.T) {
	const _testUptime = 200
	ctx, cancel := context.WithCancel(context.Background())
	metrics := &testMetrics{
		// The expected update cancels the context which causes reportMetrics to return
		setGaugeCallback: cancel,
	}

	// overwrite the variable to use mock clock.
	clk = clock.NewMock(t)
	start = clk.Now().Add(-_testUptime * time.Millisecond)
	reportMetrics(ctx, time.Nanosecond, metrics)
	assert.Equal(t,
		[]fakemetrics.MetricItem{{Type: fakemetrics.SetGaugeType, Key: []string{"uptime_in_ms"}, Val: _testUptime}},
		metrics.AllMetrics())
}

var _ telemetry.Metrics = (*testMetrics)(nil)

type testMetrics struct {
	fakemetrics.FakeMetrics
	setGaugeCallback func()
}

func (f *testMetrics) SetPrecisionGauge(key []string, val float64) {
	f.FakeMetrics.SetPrecisionGauge(key, val)
	f.setGaugeCallback()
}
