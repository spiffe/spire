package telemetry

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/armon/go-metrics"
	"github.com/armon/go-metrics/datadog"
	"github.com/armon/go-metrics/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
)

const (
	inmemInterval  = 1 * time.Second
	inmemRetention = 1 * time.Hour
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

	c *MetricsConfig

	promServer *http.Server
	inmemSink  *metrics.InmemSink
}

var _ Metrics = (*MetricsImpl)(nil)

// NewMetrics returns a Metric implementation
func NewMetrics(c *MetricsConfig) (*MetricsImpl, error) {
	var err error

	impl := &MetricsImpl{c: c}
	fanout := metrics.FanoutSink{}
	fanout = append(fanout, c.Sinks...)

	// Always add an in-memory sink
	impl.inmemSink = inmemSink()
	fanout = append(fanout, impl.inmemSink)

	if c.FileConfig.Prometheus != nil {
		sink, server, err := prometheusSink(c.FileConfig.Prometheus)
		if err != nil {
			return nil, err
		}

		impl.promServer = server
		fanout = append(fanout, sink)
	}

	for _, config := range c.FileConfig.DogStatsd {
		sink, err := dogStatsdSink(config)
		if err != nil {
			return nil, err
		}

		fanout = append(fanout, sink)
	}

	for _, config := range c.FileConfig.Statsd {
		sink, err := statsdSink(config)
		if err != nil {
			return nil, err
		}

		fanout = append(fanout, sink)
	}

	conf := metrics.DefaultConfig(c.ServiceName)
	conf.EnableHostname = false
	conf.EnableHostnameLabel = true

	impl.Metrics, err = metrics.New(conf, fanout)
	return impl, err
}

func (m *MetricsImpl) ListenAndServe(ctx context.Context) error {
	var wg sync.WaitGroup

	// Try to extract a logrus entry so we can get at the Writer() method
	// If we can't, don't bother with the signaler
	var ok bool
	var lentry *logrus.Entry
	if m.c != nil && m.c.Logger != nil {
		lentry, ok = m.c.Logger.(*logrus.Entry)
		if !ok {
			m.c.Logger.Warn("Unknown logging subsystem; Disabling telemetry signaling.")
		}
	}

	if ok && m.inmemSink != nil {
		wg.Add(1)
		signalHandler := metrics.NewInmemSignal(m.inmemSink, metrics.DefaultSignal, lentry.Writer())
		go func() {
			defer wg.Done()
			<-ctx.Done()
			signalHandler.Stop()
		}()
	}

	if m.promServer != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := m.promServer.ListenAndServe()
			if err != http.ErrServerClosed {
				m.c.Logger.Warnf("Prometheus listener stopped unexpectedly: %v", err)
			}
		}()

		wg.Add(1)
		go func() {
			defer wg.Done()
			<-ctx.Done()
			m.promServer.Close()
		}()
	}

	wg.Wait()
	return nil
}

func inmemSink() *metrics.InmemSink {
	return metrics.NewInmemSink(inmemInterval, inmemRetention)
}

func prometheusSink(c *PrometheusConfig) (Sink, *http.Server, error) {
	sink, err := prometheus.NewPrometheusSink()
	if err != nil {
		return nil, nil, err
	}

	server := &http.Server{
		Addr:    fmt.Sprintf("localhost:%d", c.Port),
		Handler: promhttp.Handler(),
	}

	return sink, server, nil
}

func dogStatsdSink(c DogStatsdConfig) (Sink, error) {
	return datadog.NewDogStatsdSink(c.Address, "")
}

func statsdSink(c StatsdConfig) (Sink, error) {
	return metrics.NewStatsdSink(c.Address)
}
