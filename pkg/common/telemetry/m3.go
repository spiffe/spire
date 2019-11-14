package telemetry

import (
	"context"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/uber-go/tally"
	"github.com/uber-go/tally/m3"
)

var (
	// buckets with decreasing granularity as latency increases
	// given these values, it is much easier to read in this format
	// than to use the iterative `MakeBuckets` functionality from tally
	durationBuckets = tally.DurationBuckets{
		0,
		time.Millisecond,
		2 * time.Millisecond,
		3 * time.Millisecond,
		4 * time.Millisecond,
		5 * time.Millisecond,
		6 * time.Millisecond,
		7 * time.Millisecond,
		8 * time.Millisecond,
		9 * time.Millisecond,
		10 * time.Millisecond,
		12 * time.Millisecond,
		14 * time.Millisecond,
		16 * time.Millisecond,
		18 * time.Millisecond,
		20 * time.Millisecond,
		25 * time.Millisecond,
		30 * time.Millisecond,
		35 * time.Millisecond,
		40 * time.Millisecond,
		45 * time.Millisecond,
		50 * time.Millisecond,
		60 * time.Millisecond,
		70 * time.Millisecond,
		80 * time.Millisecond,
		90 * time.Millisecond,
		100 * time.Millisecond,
		120 * time.Millisecond,
		140 * time.Millisecond,
		160 * time.Millisecond,
		180 * time.Millisecond,
		200 * time.Millisecond,
		250 * time.Millisecond,
		300 * time.Millisecond,
		350 * time.Millisecond,
		400 * time.Millisecond,
		450 * time.Millisecond,
		500 * time.Millisecond,
		600 * time.Millisecond,
		700 * time.Millisecond,
		800 * time.Millisecond,
		900 * time.Millisecond,
		time.Second,
		1500 * time.Millisecond,
		2 * time.Second,
		3 * time.Second,
		4 * time.Second,
		5 * time.Second,
		10 * time.Second,
	}

	// buckets for orders of magnitude of values, up to 1 million
	// given nature of SPIRE, we do not expect negative values
	exponentialValueBuckets = append(tally.ValueBuckets{0}, tally.MustMakeExponentialValueBuckets(1, 10, 6)...)
)

type m3Sink struct {
	closer io.Closer
	scope  tally.Scope
}

func newM3Sink(serviceName, address, env string) (*m3Sink, error) {
	m3Config := m3.Configuration{
		Env:      env,
		HostPort: address,
		Service:  serviceName,
	}

	r, err := m3Config.NewReporter()
	if err != nil {
		return nil, err
	}

	scopeOpts := tally.ScopeOptions{
		CachedReporter: r,
	}

	reportEvery := time.Second
	scope, closer := tally.NewRootScope(scopeOpts, reportEvery)
	sink := &m3Sink{
		closer: closer,
		scope:  scope,
	}

	return sink, nil
}

func newM3TestSink(scope tally.Scope, enableTypePrefix bool) *m3Sink {
	return &m3Sink{
		scope: scope,
	}
}

func (m *m3Sink) SetGauge(key []string, val float32) {
	m.setGauge(key, val, m.scope)
}

func (m *m3Sink) SetGaugeWithLabels(key []string, val float32, labels []Label) {
	subscope := m.subscopeWithLabels(labels)
	m.setGauge(key, val, subscope)
}

// Not implemented for m3
func (m *m3Sink) EmitKey(key []string, val float32) {}

// Counters should accumulate values
func (m *m3Sink) IncrCounter(key []string, val float32) {
	m.incrCounter(key, val, m.scope)
}

func (m *m3Sink) IncrCounterWithLabels(key []string, val float32, labels []Label) {
	subscope := m.subscopeWithLabels(labels)
	m.incrCounter(key, val, subscope)
}

// Samples are for timing information, where quantiles are used
func (m *m3Sink) AddSample(key []string, val float32) {
	m.addSample(key, val, m.scope)
}

func (m *m3Sink) AddSampleWithLabels(key []string, val float32, labels []Label) {
	subscope := m.subscopeWithLabels(labels)
	m.addSample(key, val, subscope)
}

func (m *m3Sink) subscopeWithLabels(labels []Label) tally.Scope {
	tags := labelsToTags(labels)
	return m.scope.Tagged(tags)
}

// Flattens the key for formatting, removes spaces
func (m *m3Sink) flattenKey(parts []string) string {
	// Ignore service name and type of metric as part of metric name,
	// i.e. prefer "foo_bar" to "service_counter_foo_bar"
	return strings.Join(parts[2:], "_")
}

func labelsToTags(labels []Label) map[string]string {
	tags := make(map[string]string, len(labels))
	for _, l := range labels {
		tags[l.Name] = l.Value
	}

	return tags
}

func (m *m3Sink) setGauge(key []string, val float32, scope tally.Scope) {
	gauge := m.getGauge(key, scope)
	val64 := float64(val)
	gauge.Update(val64)
}

func (m *m3Sink) getGauge(key []string, scope tally.Scope) tally.Gauge {
	flattenedKey := m.flattenKey(key)
	return scope.Gauge(flattenedKey)
}

func (m *m3Sink) incrCounter(key []string, val float32, scope tally.Scope) {
	counter := m.getCounter(key, scope)
	val64 := int64(val)
	counter.Inc(val64)
}

func (m *m3Sink) getCounter(key []string, scope tally.Scope) tally.Counter {
	flattenedKey := m.flattenKey(key)
	return scope.Counter(flattenedKey)
}

func (m *m3Sink) addSample(key []string, val float32, scope tally.Scope) {
	flattenedKey := m.flattenKey(key)
	if key[1] == "timer" {
		m.addDurationSample(flattenedKey, val, scope)
	} else {
		addValueSample(flattenedKey, val, scope)
	}
}

func (m *m3Sink) addDurationSample(flattenedKey string, val float32, scope tally.Scope) {
	histogram := scope.Histogram(flattenedKey, durationBuckets)
	dur := time.Duration(int64(val)) * timerGranularity
	histogram.RecordDuration(dur)
}

func addValueSample(flattenedKey string, val float32, scope tally.Scope) {
	histogram := scope.Histogram(flattenedKey, exponentialValueBuckets)
	val64 := float64(val)
	histogram.RecordValue(val64)
}

var _ Sink = (*m3Sink)(nil)

type m3Runner struct {
	loadedSinks []*m3Sink
}

func newM3Runner(c *MetricsConfig) (sinkRunner, error) {
	runner := &m3Runner{}
	for _, conf := range c.FileConfig.M3 {
		sink, err := newM3Sink(c.ServiceName, conf.Address, conf.Env)
		if err != nil {
			return runner, err
		}

		runner.loadedSinks = append(runner.loadedSinks, sink)
	}

	return runner, nil
}

func (r *m3Runner) isConfigured() bool {
	return len(r.loadedSinks) > 0
}

func (r *m3Runner) sinks() []Sink {
	s := make([]Sink, len(r.loadedSinks))
	for i, v := range r.loadedSinks {
		s[i] = v
	}

	return s
}

func (r *m3Runner) run(ctx context.Context) error {
	if !r.isConfigured() {
		return nil
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-ctx.Done()
		for _, s := range r.loadedSinks {
			s.closer.Close()
		}
	}()

	wg.Wait()
	return ctx.Err()
}

func (r *m3Runner) requiresTypePrefix() bool {
	return true
}
