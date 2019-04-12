package telemetry

import (
	"context"
)

var sinkRunnerFactories = []sinkRunnerFactory{
	newDogStatsdRunner,
	newInmemRunner,
	newPrometheusRunner,
	newStatsdRunner,
}

type sinkRunnerFactory func(*MetricsConfig) (sinkRunner, error)

type sinkRunner interface {
	isConfigured() bool
	sinks() []Sink

	// run blocks until context is cancelled, work is finished, or an
	// error is encountered.
	//
	// If there is nothing to do, or the work is finished, return nil.
	// Returning non-nil error will stop the agent/server.
	run(context.Context) error
}
