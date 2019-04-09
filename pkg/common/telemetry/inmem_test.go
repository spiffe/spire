package telemetry

import (
	"testing"

	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewInmemRunner(t *testing.T) {
	config := testInmemConfig()
	_, err := newInmemRunner(config)
	assert.Nil(t, err)
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
	l, hook := test.NewNullLogger()

	// Get a real logrus.Entry
	l.Debug("boo")
	entry := hook.LastEntry()

	return &MetricsConfig{
		Logger:      entry,
		ServiceName: "foo",
	}
}

func testUnknownInmemConfig() *MetricsConfig {
	l, _ := test.NewNullLogger()

	return &MetricsConfig{
		Logger:      l,
		ServiceName: "foo",
	}
}
