package telemetry

import (
	"strings"

	"github.com/DataDog/datadog-go/statsd"
)

// dogStatsdLatencySink is a DogStatsd sink that also submits each latency
// sample as a distribution named after the sample's key plus histogram. Every
// metric is otherwise formatted and submitted the same way as by the go-metrics
// DogStatsd sink.
type dogStatsdLatencySink struct {
	client *statsd.Client
}

var _ Sink = (*dogStatsdLatencySink)(nil)

func newDogStatsdLatencySink(addr string) (*dogStatsdLatencySink, error) {
	client, err := statsd.New(addr)
	if err != nil {
		return nil, err
	}
	return &dogStatsdLatencySink{client: client}, nil
}

func (s *dogStatsdLatencySink) SetGauge(key []string, val float32) {
	s.SetGaugeWithLabels(key, val, nil)
}

func (s *dogStatsdLatencySink) SetGaugeWithLabels(key []string, val float32, labels []Label) {
	s.SetPrecisionGaugeWithLabels(key, float64(val), labels)
}

func (s *dogStatsdLatencySink) SetPrecisionGauge(key []string, val float64) {
	s.SetPrecisionGaugeWithLabels(key, val, nil)
}

func (s *dogStatsdLatencySink) SetPrecisionGaugeWithLabels(key []string, val float64, labels []Label) {
	_ = s.client.Gauge(dogStatsdName(key), val, dogStatsdTags(labels), 1)
}

// EmitKey is not implemented, since DogStatsd has no metric type that holds an
// arbitrary number of values.
func (s *dogStatsdLatencySink) EmitKey([]string, float32) {}

func (s *dogStatsdLatencySink) IncrCounter(key []string, val float32) {
	s.IncrCounterWithLabels(key, val, nil)
}

func (s *dogStatsdLatencySink) IncrCounterWithLabels(key []string, val float32, labels []Label) {
	_ = s.client.Count(dogStatsdName(key), int64(val), dogStatsdTags(labels), 1)
}

func (s *dogStatsdLatencySink) AddSample(key []string, val float32) {
	s.AddSampleWithLabels(key, val, nil)
}

func (s *dogStatsdLatencySink) AddSampleWithLabels(key []string, val float32, labels []Label) {
	tags := dogStatsdTags(labels)
	_ = s.client.TimeInMilliseconds(dogStatsdName(key), float64(val), tags, 1)
	if isLatencySample(key) {
		_ = s.client.Distribution(dogStatsdName(latencyHistogramKey(key)), float64(val), tags, 1)
	}
}

// Shutdown flushes buffered metrics and closes the client.
func (s *dogStatsdLatencySink) Shutdown() {
	_ = s.client.Close()
}

// dogStatsdName matches the go-metrics DogStatsd sink created without a host
// name, which removes the first empty key element before joining the key.
func dogStatsdName(key []string) string {
	for i, part := range key {
		if part == "" {
			key = append(append([]string{}, key[:i]...), key[i+1:]...)
			break
		}
	}
	return strings.Map(dogStatsdSanitize, strings.Join(key, "."))
}

func dogStatsdTags(labels []Label) []string {
	var tags []string
	for _, l := range labels {
		name := strings.Map(dogStatsdSanitize, l.Name)
		value := strings.Map(dogStatsdSanitize, l.Value)
		if value == "" {
			tags = append(tags, name)
			continue
		}
		tags = append(tags, name+":"+value)
	}
	return tags
}

func dogStatsdSanitize(r rune) rune {
	if r == ':' || r == ' ' {
		return '_'
	}
	return r
}
