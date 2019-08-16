package telemetry

import (
	"context"
	"testing"
	"time"

	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDogStatsdIsConfigured(t *testing.T) {
	config := testDogStatsdConfig()
	dr, err := newDogStatsdRunner(config)
	require.Nil(t, err)
	assert.True(t, dr.isConfigured())

	config.FileConfig.DogStatsd = []DogStatsdConfig{}
	dr, err = newDogStatsdRunner(config)
	require.Nil(t, err)
	assert.False(t, dr.isConfigured())
}

func TestDogStatsdSinks(t *testing.T) {
	config := testDogStatsdConfig()
	sink2 := DogStatsdConfig{
		Address: "localhost:8126",
	}
	config.FileConfig.DogStatsd = append(config.FileConfig.DogStatsd, sink2)

	dr, err := newDogStatsdRunner(config)
	require.Nil(t, err)
	assert.Equal(t, 2, len(dr.sinks()))
}

func TestDogStatsdRun(t *testing.T) {
	config := testDogStatsdConfig()
	dr, err := newDogStatsdRunner(config)
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

func testDogStatsdConfig() *MetricsConfig {
	l, _ := test.NewNullLogger()

	return &MetricsConfig{
		Logger:      l,
		ServiceName: "foo",
		FileConfig: FileConfig{
			DogStatsd: []DogStatsdConfig{
				{
					Address: "localhost:8125",
				},
			},
		},
	}
}
