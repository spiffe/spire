package log

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOpenLogFileAppends(t *testing.T) {
	dir := spiretest.TempDir(t)
	logPath := filepath.Join(dir, "test.log")
	require.NoError(t, os.WriteFile(logPath, []byte("existing\n"), fileMode))

	f, err := openLogFile(logPath)
	require.NoError(t, err)

	_, err = f.Write([]byte("appended\n"))
	require.NoError(t, err)
	require.NoError(t, f.Close())

	content, err := os.ReadFile(logPath)
	require.NoError(t, err)
	assert.Equal(t, "existing\nappended\n", string(content))
}

func TestOpenLogFileCreatesMissingFile(t *testing.T) {
	dir := spiretest.TempDir(t)
	logPath := filepath.Join(dir, "test.log")

	f, err := openLogFile(logPath)
	require.NoError(t, err)
	require.NoError(t, f.Close())

	assert.FileExists(t, logPath)
}

func TestOpenLogFileFailsOnMissingDirectory(t *testing.T) {
	logPath := filepath.Join(spiretest.TempDir(t), "nope", "test.log")

	_, err := openLogFile(logPath)
	require.Error(t, err)
}
