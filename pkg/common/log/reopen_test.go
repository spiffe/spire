package log

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReopenOnSignalWithReopenableOutputFileSuccess(t *testing.T) {
	const (
		_tempDir         = "spirelogrotatetest"
		_testLogFileName = "test.log"
		_rotatedSuffix   = "rotated"
		_firstMsg        = "a message"
		_secondMsg       = "another message"
	)
	dir := spiretest.TempDir(t)

	logFileName := filepath.Join(dir, _testLogFileName)
	rotatedLogFileName := logFileName + "." + _rotatedSuffix
	rwc, err := NewReopenableFile(logFileName)
	require.NoError(t, err)

	fsInfo, err := rwc.f.Stat()
	require.NoError(t, err)
	assert.Equal(t, int64(0), fsInfo.Size(), "%s should be empty", fsInfo.Name())

	logger, err := NewLogger(WithReopenableOutputFile(rwc))
	require.NoError(t, err)

	logger.Warning(_firstMsg)

	fsInfo, err = rwc.f.Stat()
	require.NoError(t, err)
	initialLogSize := fsInfo.Size()
	initialLogModTime := fsInfo.ModTime()
	assert.NotEqual(t, int64(0), fsInfo.Size(), "%s should not be empty", fsInfo.Name())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	signalCh := make(chan os.Signal, 1)

	renamedCh := make(chan struct{})
	go func() {
		// emulate logrotate
		err = os.Rename(logFileName, rotatedLogFileName)
		require.NoError(t, err)
		signalCh <- reopenSignal
		// explicitly cancel so test continues
		cancel()
		close(renamedCh)
	}()
	err = reopenOnSignal(ctx, rwc, signalCh)
	require.NoError(t, err, "reopen should succeed")
	<-renamedCh
	fsInfo, err = rwc.f.Stat()
	require.NoError(t, err)
	assert.Equal(t, int64(0), fsInfo.Size(), "%s should be empty again", fsInfo.Name())

	rotatedLog, err := os.Open(rotatedLogFileName)
	require.NoError(t, err)
	fsInfo, err = rotatedLog.Stat()
	require.NoError(t, err)
	assert.Equal(t, initialLogSize, fsInfo.Size(), "%s should be same size as before rename", fsInfo.Name())
	assert.Equal(t, initialLogModTime, fsInfo.ModTime(), "%s should have same mod time as before rename", fsInfo.Name())

	logger.Warning(_secondMsg)
	fsInfo, err = rwc.f.Stat()
	require.NoError(t, err)
	assert.NotEqual(t, int64(0), fsInfo.Size(), "%s should not be empty", fsInfo.Name())
	assert.NotEqual(t, initialLogSize, fsInfo.Size(), "%s should not be same size as initial file", fsInfo.Name())
}

func TestReopenOnSignalError(t *testing.T) {
	const _msg = "filesystem broken"
	fakeErr := errors.New(_msg)
	rwc := &fakeReopenerError{err: errors.New(_msg)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	signalCh := make(chan os.Signal, 1)

	go func() {
		// trigger reopen error
		signalCh <- reopenSignal
	}()
	err := reopenOnSignal(ctx, rwc, signalCh)
	require.True(t, errors.As(err, &fakeErr), "expected %s, got %s", _msg, err.Error())
}

// test helpers
var _ Reopener = (*fakeReopenerError)(nil)

type fakeReopenerError struct {
	err error
}

func (f *fakeReopenerError) Reopen() error {
	if f.err != nil {
		return f.err
	}
	return nil
}
