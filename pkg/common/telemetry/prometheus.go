package telemetry

import (
	"context"
	"fmt"
	"net/http"
	"sync"

	prommetrics "github.com/armon/go-metrics/prometheus"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
)

type prometheusRunner struct {
	c      *PrometheusConfig
	log    logrus.FieldLogger
	server *http.Server
	sink   Sink
}

func newPrometheusRunner(c *MetricsConfig) (sinkRunner, error) {
	runner := &prometheusRunner{
		c:   c.FileConfig.Prometheus,
		log: c.Logger,
	}

	if runner.c == nil {
		return runner, nil
	}

	var err error
	runner.sink, err = prommetrics.NewPrometheusSink()
	if err != nil {
		return runner, err
	}

	handlerOpts := promhttp.HandlerOpts{
		ErrorLog: runner.log,
	}
	handler := promhttp.HandlerFor(prometheus.DefaultGatherer, handlerOpts)

	if runner.c.Host == "" {
		runner.c.Host = "localhost"
	}

	if runner.c.Host != "localhost" {
		runner.log.Warnf("Agent is now configured to accept remote network connections for Prometheus stats collection. Please ensure access to this port is tightly controlled.")
	}

	runner.server = &http.Server{
		Addr:    fmt.Sprintf("%s:%d", runner.c.Host, runner.c.Port),
		Handler: handler,
	}

	return runner, nil
}

func (p *prometheusRunner) isConfigured() bool {
	return p.c != nil
}

func (p *prometheusRunner) sinks() []Sink {
	if p.isConfigured() != true {
		return []Sink{}
	}

	return []Sink{p.sink}
}

func (p *prometheusRunner) run(ctx context.Context) error {
	if p.isConfigured() != true {
		return nil
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		err := p.server.ListenAndServe()
		if err != http.ErrServerClosed {
			p.log.Warnf("Prometheus listener stopped unexpectedly: %v", err)
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		<-ctx.Done()
		p.server.Close()
	}()

	wg.Wait()
	return ctx.Err()
}

func (p *prometheusRunner) requiresTypePrefix() bool {
	return false
}
