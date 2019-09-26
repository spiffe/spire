package telemetry

import (
	"context"
	"sync"
	"time"

	"github.com/armon/go-metrics"
	"github.com/sirupsen/logrus"
)

const (
	inmemInterval  = 1 * time.Second
	inmemRetention = 1 * time.Hour
)

type inmemRunner struct {
	log        *logrus.Entry
	loadedSink *metrics.InmemSink
}

func newInmemRunner(c *MetricsConfig) (sinkRunner, error) {
	runner := &inmemRunner{}

	if entry, ok := c.Logger.(*logrus.Entry); ok {
		runner.log = entry
	} else {
		c.Logger.Warn("Unknown logging subsystem; disabling telemetry signaling.")
		return runner, nil
	}

	runner.loadedSink = metrics.NewInmemSink(inmemInterval, inmemRetention)
	return runner, nil
}

func (i *inmemRunner) isConfigured() bool {
	return i.loadedSink != nil
}

func (i *inmemRunner) sinks() []Sink {
	if i.isConfigured() != true {
		return []Sink{}
	}

	return []Sink{i.loadedSink}
}

func (i *inmemRunner) run(ctx context.Context) error {
	if i.isConfigured() != true {
		return nil
	}

	var wg sync.WaitGroup
	wg.Add(1)
	signalHandler := metrics.NewInmemSignal(i.loadedSink, metrics.DefaultSignal, i.log.Writer())
	go func() {
		defer wg.Done()
		<-ctx.Done()
		signalHandler.Stop()
	}()

	wg.Wait()
	return nil
}

func (i *inmemRunner) requiresTypePrefix() bool {
	return false
}
