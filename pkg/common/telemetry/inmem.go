package telemetry

import (
	"context"
	"io"
	"time"

	"github.com/armon/go-metrics"
	"github.com/sirupsen/logrus"
)

const (
	inmemInterval  = 1 * time.Second
	inmemRetention = 1 * time.Hour
)

type inmemRunner struct {
	log        logrus.FieldLogger
	w          io.Writer
	loadedSink *metrics.InmemSink
}

func newInmemRunner(c *MetricsConfig) (sinkRunner, error) {
	runner := &inmemRunner{
		log: c.Logger,
	}

	// Don't enable If the InMem block is not present.
	inMem := c.FileConfig.InMem
	if inMem == nil {
		return runner, nil
	}

	if logger, ok := c.Logger.(interface{ Writer() *io.PipeWriter }); ok {
		runner.w = logger.Writer()
	} else {
		c.Logger.Warn("Unknown logging subsystem; disabling telemetry signaling")
		return runner, nil
	}

	runner.loadedSink = metrics.NewInmemSink(inmemInterval, inmemRetention)
	return runner, nil
}

func (i *inmemRunner) isConfigured() bool {
	return i.loadedSink != nil
}

func (i *inmemRunner) sinks() []Sink {
	if !i.isConfigured() {
		return []Sink{}
	}

	return []Sink{i.loadedSink}
}

func (i *inmemRunner) run(ctx context.Context) error {
	if !i.isConfigured() {
		return nil
	}

	signalHandler := metrics.NewInmemSignal(i.loadedSink, metrics.DefaultSignal, i.w)
	defer signalHandler.Stop()
	<-ctx.Done()
	return nil
}

func (i *inmemRunner) requiresTypePrefix() bool {
	return false
}
