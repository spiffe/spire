package telemetry

import (
	"context"

	"github.com/hashicorp/go-metrics/datadog"
)

type dogStatsdRunner struct {
	loadedSinks []Sink
}

func newDogStatsdRunner(c *MetricsConfig) (sinkRunner, error) {
	runner := &dogStatsdRunner{}

	for _, dc := range c.FileConfig.DogStatsd {
		sink, err := newDogStatsdSink(dc.Address, latencyHistogramsEnabled(c.FileConfig))
		if err != nil {
			return nil, err
		}

		runner.loadedSinks = append(runner.loadedSinks, sink)
	}

	return runner, nil
}

func newDogStatsdSink(addr string, latencyDistributions bool) (Sink, error) {
	if latencyDistributions {
		return newDogStatsdLatencySink(addr)
	}
	return datadog.NewDogStatsdSink(addr, "")
}

func (d *dogStatsdRunner) isConfigured() bool {
	return len(d.loadedSinks) > 0
}

func (d *dogStatsdRunner) sinks() []Sink {
	return d.loadedSinks
}

func (d *dogStatsdRunner) run(context.Context) error {
	// Nothing to do here
	return nil
}

func (d *dogStatsdRunner) requiresTypePrefix() bool {
	return false
}
