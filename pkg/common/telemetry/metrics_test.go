package telemetry

import (
	"context"
	"testing"
	"time"

	"github.com/sirupsen/logrus/hooks/test"
)

func TestNewMetrics(t *testing.T) {
	c := defaultMetricsConfig()
	_, err := NewMetrics(c)
	if err != nil {
		t.Errorf("want: nil; got: %v", err)
	}

	c.FileConfig.DogStatsd = []DogStatsdConfig{
		DogStatsdConfig{Address: "i'm a bad address"},
	}
	_, err = NewMetrics(c)
	if err == nil {
		t.Error("want: error; got: nil")
	}

	c.FileConfig.Statsd = []StatsdConfig{
		StatsdConfig{Address: "i'm a bad address"},
	}
	_, err = NewMetrics(c)
	if err == nil {
		t.Error("want: error; got: nil")
	}
}

func TestListenAndServeWithNoConfig(t *testing.T) {
	ctx, _ := context.WithTimeout(context.Background(), time.Minute)

	m := new(MetricsImpl)
	m.ListenAndServe(ctx)

	if ctx.Err() != nil {
		t.Errorf("want: nil; got: %v", ctx.Err())
	}
}

func TestListenAndServeShutdown(t *testing.T) {
	// Put prometheus listener on a random port
	config := defaultMetricsConfig()
	config.FileConfig.Prometheus = &PrometheusConfig{}

	m, err := NewMetrics(config)
	if err != nil {
		t.Fatalf("want: nil; got: %v", err)
	}

	errCh := make(chan error)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		errCh <- m.ListenAndServe(ctx)
	}()

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("want: nil; got: %v", err)
		}
	case <-time.NewTimer(1 * time.Minute).C:
		t.Error("want: nil return; got: timeout")
	}
}

func defaultMetricsConfig() *MetricsConfig {
	l, _ := test.NewNullLogger()

	return &MetricsConfig{
		Logger:      l,
		ServiceName: "foo",
	}
}
