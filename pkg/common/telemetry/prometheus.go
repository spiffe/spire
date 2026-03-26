package telemetry

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	prommetrics "github.com/hashicorp/go-metrics/prometheus"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/util"
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
	runner.sink, err = prommetrics.NewPrometheusSinkFrom(prommetrics.PrometheusOpts{})
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
		runner.log.Warnf("Agent is now configured to accept remote network connections for Prometheus stats collection. Please ensure access to this port is tightly controlled")
	}

	runner.log.WithFields(logrus.Fields{
		"host": runner.c.Host,
		"port": runner.c.Port,
	}).Info("Starting prometheus exporter")

	runner.server = &http.Server{
		Addr:              fmt.Sprintf("%s:%d", runner.c.Host, runner.c.Port),
		Handler:           handler,
		ReadHeaderTimeout: time.Second * 10,
	}

	if runner.c.TLS != nil {
		tlsCfg, tlsCfgErr := runner.newTLSConfig()
		if tlsCfgErr != nil {
			return runner, fmt.Errorf("failed to create TLS config for Prometheus: %w", tlsCfgErr)
		}
		runner.server.TLSConfig = tlsCfg
	}

	return runner, nil
}

func (p *prometheusRunner) isConfigured() bool {
	return p.c != nil
}

func (p *prometheusRunner) sinks() []Sink {
	if !p.isConfigured() {
		return []Sink{}
	}

	return []Sink{p.sink}
}

func (p *prometheusRunner) run(ctx context.Context) error {
	if !p.isConfigured() {
		return nil
	}

	var wg sync.WaitGroup
	wg.Go(func() {
		var err error
		if p.server.TLSConfig != nil {
			err = p.server.ListenAndServeTLS("", "")
		} else {
			err = p.server.ListenAndServe()
		}
		if !errors.Is(err, http.ErrServerClosed) {
			p.log.Warnf("Prometheus listener stopped unexpectedly: %v", err)
		}
	})

	wg.Go(func() {
		<-ctx.Done()
		p.server.Close()
	})

	wg.Wait()
	return ctx.Err()
}

func (p *prometheusRunner) requiresTypePrefix() bool {
	return false
}

func (p *prometheusRunner) newTLSConfig() (*tls.Config, error) {
	certificate, err := tls.LoadX509KeyPair(p.c.TLS.CertFile, p.c.TLS.KeyFile)
	if err != nil {
		return nil, err
	}

	// easier to return the tls config rather than assigning it to the server directly from maintenance perspective
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS12,
	}

	var caCertPool *x509.CertPool
	if p.c.TLS.ClientCAFile != "" {
		caCertPool, err = util.LoadCertPool(p.c.TLS.ClientCAFile)
		if err != nil {
			return nil, err
		}

		tlsCfg.ClientCAs = caCertPool
		tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
	}

	return tlsCfg, nil
}
