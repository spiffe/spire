package telemetry

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	defaultStatsdTestListenerPort = 8125
	statsdProtocol                = "udp"
)

func TestStatsdIsConfigured(t *testing.T) {
	config := testStatsdConfig()
	dr, err := newStatsdRunner(config)
	require.Nil(t, err)
	assert.True(t, dr.isConfigured())

	config.FileConfig.Statsd = []StatsdConfig{}
	dr, err = newStatsdRunner(config)
	require.Nil(t, err)
	assert.False(t, dr.isConfigured())
}

func TestStatsdSinks(t *testing.T) {
	config := testStatsdConfig()
	sink2 := StatsdConfig{
		Address: "localhost:8126",
	}
	config.FileConfig.Statsd = append(config.FileConfig.Statsd, sink2)

	dr, err := newStatsdRunner(config)
	require.Nil(t, err)
	assert.Equal(t, 2, len(dr.sinks()))
}

func TestStatsdRun(t *testing.T) {
	config := testStatsdConfig()
	dr, err := newStatsdRunner(config)
	require.Nil(t, err)

	errCh := make(chan error)
	go func() {
		errCh <- dr.run(context.Background())
	}()

	select {
	case err = <-errCh:
		assert.Nil(t, err)
	case <-time.After(time.Minute):
		t.Error("run should return nil immediately")
	}
}

func testStatsdConfigWithPort(port int) *MetricsConfig {
	l, _ := test.NewNullLogger()

	return &MetricsConfig{
		Logger:      l,
		ServiceName: "foo",
		FileConfig: FileConfig{
			Statsd: []StatsdConfig{
				{
					Address: fmt.Sprintf("127.0.0.1:%d", port),
				},
			},
		},
	}
}

func testStatsdConfig() *MetricsConfig {
	return testStatsdConfigWithPort(defaultStatsdTestListenerPort)
}
