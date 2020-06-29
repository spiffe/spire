package log

import (
	"testing"

	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHCLogAdapterImpliedArgs(t *testing.T) {
	testHook := test.Hook{}

	// Set up a logger with a test hook
	logger, err := NewLogger(WithLevel("warning"),
		func(logger *Logger) error {
			logger.AddHook(&testHook)
			return nil
		})
	require.NoError(t, err)

	adapter := NewHCLogAdapter(logger, "test")
	assert.Equal(t, ([]interface{})(nil), adapter.ImpliedArgs())

	adapter2 := adapter.With("a", "b", "c", "d")
	assert.Equal(t, []interface{}{"a", "b", "c", "d"}, adapter2.ImpliedArgs())

	adapter3 := adapter2.With("x", "y", "z", "w")
	assert.Equal(t, []interface{}{"a", "b", "c", "d", "x", "y", "z", "w"}, adapter3.ImpliedArgs())
}
