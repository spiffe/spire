package telemetry

import (
	"context"
	"errors"
	"time"

	"github.com/armon/go-metrics"
	"github.com/spiffe/spire/pkg/common/util"
)

type Label = metrics.Label
type Sink = metrics.MetricSink

type Metrics interface {
	// A Gauge should retain the last value it is set to
	SetGauge(key []string, val float32)
	SetGaugeWithLabels(key []string, val float32, labels []Label)

	// Should emit a Key/Value pair for each call
	EmitKey(key []string, val float32)

	// Counters should accumulate values
	IncrCounter(key []string, val float32)
	IncrCounterWithLabels(key []string, val float32, labels []Label)

	// Samples are for timing information, where quantiles are used
	AddSample(key []string, val float32)
	AddSampleWithLabels(key []string, val float32, labels []Label)

	// A convenience function for measuring elapsed time with a single line
	MeasureSince(key []string, start time.Time)
	MeasureSinceWithLabels(key []string, start time.Time, labels []Label)
}

type MetricsImpl struct {
	*metrics.Metrics

	c       *MetricsConfig
	runners []sinkRunner
}

var _ Metrics = (*MetricsImpl)(nil)

// NewMetrics returns a Metric implementation
func NewMetrics(c *MetricsConfig) (*MetricsImpl, error) {
	if c.Logger == nil {
		return nil, errors.New("logger must be configured")
	}

	impl := &MetricsImpl{c: c}
	fanout := metrics.FanoutSink{}
	fanout = append(fanout, c.Sinks...)

	for _, f := range sinkRunnerFactories {
		runner, err := f(c)
		if err != nil {
			return nil, err
		}

		if runner.isConfigured() {
			fanout = append(fanout, runner.sinks()...)
			impl.runners = append(impl.runners, runner)
		}
	}

	conf := metrics.DefaultConfig(c.ServiceName)
	conf.EnableHostname = false
	conf.EnableHostnameLabel = true

	var err error
	impl.Metrics, err = metrics.New(conf, fanout)
	if err != nil {
		return nil, err
	}

	return impl, nil
}

func (m *MetricsImpl) ListenAndServe(ctx context.Context) error {
	var tasks []func(context.Context) error
	for _, runner := range m.runners {
		tasks = append(tasks, runner.run)
	}

	return util.RunTasks(ctx, tasks...)
}
