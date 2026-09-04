package log

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Fails with os.OpenFile, which does not pass FILE_SHARE_DELETE.
func TestOpenLogFileAllowsExternalRename(t *testing.T) {
	dir := spiretest.TempDir(t)
	logPath := filepath.Join(dir, "test.log")
	rotated := filepath.Join(dir, "test.log.1")

	f, err := openLogFile(logPath)
	require.NoError(t, err)
	defer func() {
		_ = f.Close()
	}()

	_, err = f.WriteString("before rename")
	require.NoError(t, err)

	require.NoError(t, os.Rename(logPath, rotated), "the log file must be renameable while it is open")

	// The handle follows the file across the rename, as it does on POSIX.
	_, err = f.WriteString(" after rename")
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

	_, err = f.WriteString("content")
	require.NoError(t, err)

	assert.NoError(t, os.Remove(logPath), "the log file must be deletable while it is open")
}

// The link count is the only thing this package assumes about how Windows
// reports a deleted file, and a wrong assumption would leave fileDeleted always
// false, quietly disabling the recovery in Reopen. Assert it against the real
// filesystem so CI says so instead.
func TestFileDeleted(t *testing.T) {
	dir := spiretest.TempDir(t)
	logPath := filepath.Join(dir, "test.log")

	f, err := openLogFile(logPath)
	require.NoError(t, err)
	defer func() {
		_ = f.Close()
	}()

	assert.False(t, fileDeleted(f), "a file that is still linked")

	// FILE_SHARE_DELETE lets this succeed while the handle is open.
	require.NoError(t, os.Remove(logPath))
	assert.True(t, fileDeleted(f), "a file deleted while the handle is open")
}

// Moving a file aside leaves it linked under the new name, so a rename must not
// look like a delete. Reopen would otherwise drop a working descriptor on the
// flow logrotate uses.
func TestFileDeletedAfterRename(t *testing.T) {
	dir := spiretest.TempDir(t)
	logPath := filepath.Join(dir, "test.log")

	f, err := openLogFile(logPath)
	require.NoError(t, err)
	defer func() {
		_ = f.Close()
	}()

	require.NoError(t, os.Rename(logPath, filepath.Join(dir, "test.log.1")))
	assert.False(t, fileDeleted(f), "a renamed file is still linked")
}

func TestFileDeletedWithoutFile(t *testing.T) {
	assert.False(t, fileDeleted(nil))
}
