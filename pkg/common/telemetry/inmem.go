package telemetry

import (
	"context"
	"io"
	"os"
	"os/signal"
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
	log        logrus.FieldLogger
	w          io.Writer
	loadedSink *metrics.InmemSink

	inMemBlockSet bool
}

func newInmemRunner(c *MetricsConfig) (sinkRunner, error) {
	runner := &inmemRunner{
		log: c.Logger,
	}

	if c.FileConfig.InMem != nil && c.FileConfig.InMem.Enabled != nil {
		runner.inMemBlockSet = true

		if !*c.FileConfig.InMem.Enabled {
			return runner, nil
		}
	}

	if logger, ok := c.Logger.(interface{ Writer() *io.PipeWriter }); ok {
		runner.w = logger.Writer()
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

	i.startInMemMetrics(ctx, &wg)

	if !i.inMemBlockSet {
		i.startConfigWarning(ctx, &wg)
	}

	wg.Wait()
	return nil
}

func (i *inmemRunner) startConfigWarning(ctx context.Context, wg *sync.WaitGroup) {
	wg.Add(1)
	sigChannel := make(chan os.Signal, 1)
	signal.Notify(sigChannel, metrics.DefaultSignal)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-sigChannel:
				i.log.Warn("The in-memory telemetry sink will be disabled by default in a future release." +
					" If you wish to continue using it, please enable it in the telemetry configuration.")
			case <-ctx.Done():
				signal.Stop(sigChannel)
				return
			}
		}
	}()
}

func (i *inmemRunner) startInMemMetrics(ctx context.Context, wg *sync.WaitGroup) {
	wg.Add(1)
	signalHandler := metrics.NewInmemSignal(i.loadedSink, metrics.DefaultSignal, i.w)
	go func() {
		defer wg.Done()
		<-ctx.Done()
		signalHandler.Stop()
	}()
}

func (i *inmemRunner) requiresTypePrefix() bool {
	return false
}
