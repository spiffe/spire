package telemetry

import (
	"context"

	"github.com/armon/go-metrics"
)

type statsdRunner struct {
	loadedSinks []Sink
}

func newStatsdRunner(c *MetricsConfig) (sinkRunner, error) {
	runner := &statsdRunner{}

	for _, sc := range c.FileConfig.Statsd {
		sink, err := metrics.NewStatsdSink(sc.Address)
		if err != nil {
			return runner, nil
		}

		runner.loadedSinks = append(runner.loadedSinks, sink)
	}

	return runner, nil
}

func (s *statsdRunner) isConfigured() bool {
	return len(s.loadedSinks) > 0
}

func (s *statsdRunner) sinks() []Sink {
	return s.loadedSinks
}

func (s *statsdRunner) run(context.Context) error {
	// Nothing to do here
	return nil
}

func (s *statsdRunner) requiresTypePrefix() bool {
	return false
}
