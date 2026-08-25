package log

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// An external rotator has to be able to move the log file aside while SPIRE is
// writing to it. That only works if the file is opened with FILE_SHARE_DELETE,
// which os.OpenFile does not pass.
func TestOpenLogFileAllowsExternalRename(t *testing.T) {
	dir := spiretest.TempDir(t)
	logPath := filepath.Join(dir, "test.log")
	rotated := filepath.Join(dir, "test.log.1")

	f, err := openLogFile(logPath)
	require.NoError(t, err)
	defer func() {
		_ = f.Close()
	}()

	_, err = f.Write([]byte("before rename"))
	require.NoError(t, err)

	require.NoError(t, os.Rename(logPath, rotated), "the log file must be renameable while it is open")

	// The handle follows the file across the rename, as it does on POSIX, so
	// writes keep landing in the rotated file until the reopen happens.
	_, err = f.Write([]byte(" after rename"))
	require.NoError(t, err)
	require.NoError(t, f.Close())

	content, err := os.ReadFile(rotated)
	require.NoError(t, err)
	assert.Equal(t, "before rename after rename", string(content))
	assert.NoFileExists(t, logPath)
}

func TestOpenLogFileAllowsExternalDelete(t *testing.T) {
	dir := spiretest.TempDir(t)
	logPath := filepath.Join(dir, "test.log")

	f, err := openLogFile(logPath)
	require.NoError(t, err)
	defer func() {
		_ = f.Close()
	}()

	_, err = f.Write([]byte("content"))
	require.NoError(t, err)

	assert.NoError(t, os.Remove(logPath), "the log file must be deletable while it is open")
}
