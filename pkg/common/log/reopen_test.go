package log

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReopenOnSignal(t *testing.T) {
	const (
		_tempDir         = "spirelogrotatetest"
		_testLogFileName = "test.log"
		_rotatedSuffix   = "rotated"
		_firstMsg        = "a message"
		_secondMsg       = "another message"
	)
	dir, err := os.MkdirTemp("", _tempDir)
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	logFileName := filepath.Join(dir, _testLogFileName)
	rotatedLogFileName := logFileName + "." + _rotatedSuffix
	rf, err := NewReopenableFile(logFileName)
	require.NoError(t, err)

	fsInfo, err := rf.f.Stat()
	require.NoError(t, err)
	assert.Equal(t, int64(0), fsInfo.Size(), "%s should be empty", fsInfo.Name())

	logger, err := NewLogger(WithReopenableOutputFile(rf))
	require.NoError(t, err)

	logger.Warning(_firstMsg)

	fsInfo, err = rf.f.Stat()
	require.NoError(t, err)
	initialLogSize := fsInfo.Size()
	assert.NotEqual(t, int64(0), fsInfo.Size(), "%s should not be empty", fsInfo.Name())

	signalCh := make(chan os.Signal, 1)
	// prevent test from hanging until test runner timeout when failing
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()

	renamedCh := make(chan struct{})
	go func() {
		// emulate logrotate
		err = os.Rename(logFileName, rotatedLogFileName)
		require.NoError(t, err)
		signalCh <- _reopenSignal
		close(renamedCh)
	}()
	reopenOnSignal(ctx, rf, signalCh)
	<-renamedCh
	fsInfo, err = rf.f.Stat()
	require.NoError(t, err)
	assert.Equal(t, int64(0), fsInfo.Size(), "%s should be empty again", fsInfo.Name())

	rotatedLog, err := os.Open(rotatedLogFileName)
	require.NoError(t, err)
	fsInfo, err = rotatedLog.Stat()
	require.NoError(t, err)
	assert.Equal(t, initialLogSize, fsInfo.Size(), "%s should be same size as before rename", fsInfo.Name())

	logger.Warning(_secondMsg)
	fsInfo, err = rf.f.Stat()
	require.NoError(t, err)
	assert.NotEqual(t, int64(0), fsInfo.Size(), "%s should not be empty", fsInfo.Name())
	assert.NotEqual(t, initialLogSize, fsInfo.Size(), "%s should not be same size as initial file", fsInfo.Name())
}
