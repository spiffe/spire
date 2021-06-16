package spiretest

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TempDir creates a temporary directory that is cleaned up when the test
// finishes.
// TODO: remove when go1.15 is out, which introduces a new method on
// *testing.T for this purpose.
func TempDir(tb testing.TB) string {
	dir, err := os.MkdirTemp("", "spire-test-")
	require.NoError(tb, err)
	tb.Cleanup(func() {
		assert.NoError(tb, os.RemoveAll(dir))
	})
	return dir
}
