package telemetry

import (
	"context"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/armon/go-metrics"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/test/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewInmemRunner(t *testing.T) {
	config := testInmemConfig()
	_, err := newInmemRunner(config)
	assert.Nil(t, err)
}

func TestDefaultEnabledNewInmemRunner(t *testing.T) {
	t.Run("enabled when block undeclared", func(t *testing.T) {
		runner, err := newInmemRunner(testInmemConfig())
		assert.Nil(t, err)
		assert.True(t, runner.isConfigured())
	})

	t.Run("enabled flag undeclared", func(t *testing.T) {
		config := testInmemConfig()
		config.FileConfig = FileConfig{
			InMem: &InMem{},
		}
		runner, err := newInmemRunner(config)
		assert.Nil(t, err)
		assert.True(t, runner.isConfigured())
	})

	t.Run("enabled flag declared", func(t *testing.T) {
		enabledFlag := true

		config := testInmemConfig()
		config.FileConfig = FileConfig{
			InMem: &InMem{
				Enabled: &enabledFlag,
			},
		}
		runner, err := newInmemRunner(config)
		assert.Nil(t, err)
		assert.True(t, runner.isConfigured())
	})
}

func TestDisabledNewInmemRunner(t *testing.T) {
	enabledFlag := false

	config := &MetricsConfig{
		ServiceName: "foo",
		FileConfig: FileConfig{
			InMem: &InMem{
				Enabled: &enabledFlag,
			},
		},
	}
	runner, err := newInmemRunner(config)
	assert.Nil(t, err)
	assert.False(t, runner.isConfigured())
}

func TestWarnOnFutureDisable(t *testing.T) {
	logger, hook := test.NewNullLogger()

	// Get a real logrus.Entry
	logger.SetLevel(logrus.DebugLevel)
	c := &MetricsConfig{
		Logger:      logger,
		ServiceName: "foo",
	}

	ir, err := newInmemRunner(c)
	require.Nil(t, err)
	require.Equal(t, 1, len(ir.sinks()))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- ir.run(ctx)
	}()

	// Send signal, wait for signal handling + logging
	util.RunWithTimeout(t, time.Minute, func() {
		for {
			require.NoError(t, syscall.Kill(os.Getpid(), metrics.DefaultSignal))

			require.NoError(t, ctx.Err())

			if entry := hook.LastEntry(); entry != nil {
				assert.Equal(t, "The in-memory telemetry sink will be disabled by default in a future release."+
					" If you wish to continue using it, please enable it in the telemetry configuration", entry.Message)
				return
			}
		}
	})

	cancel()
	require.NoError(t, <-errCh)
}

func TestInmemSinks(t *testing.T) {
	ir, err := newInmemRunner(testUnknownInmemConfig())
	require.Nil(t, err)
	assert.Equal(t, 0, len(ir.sinks()))

	ir, err = newInmemRunner(testInmemConfig())
	require.Nil(t, err)
	assert.Equal(t, 1, len(ir.sinks()))
}

func TestInmemIsConfigured(t *testing.T) {
	ir, err := newInmemRunner(testInmemConfig())
	require.Nil(t, err)
	assert.True(t, ir.isConfigured())

	ir, err = newInmemRunner(testUnknownInmemConfig())
	require.Nil(t, err)
	assert.False(t, ir.isConfigured())
}

func testInmemConfig() *MetricsConfig {
	l, _ := test.NewNullLogger()
	return &MetricsConfig{
		Logger:      l,
		ServiceName: "foo",
	}
}

func testUnknownInmemConfig() *MetricsConfig {
	l, _ := test.NewNullLogger()

	// unknownLogger only provides logrus.FieldLogger interface and does not give
	// access to the underlying writer via the Writer() method.
	unknownLogger := struct {
		logrus.FieldLogger
	}{
		FieldLogger: l,
	}

	return &MetricsConfig{
		Logger:      unknownLogger,
		ServiceName: "foo",
	}
}
