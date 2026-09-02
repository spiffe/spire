package log

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A size triggered rotation fails inside Write, which cannot report it. Without
// the drain a Windows deployment would grow the log with nothing said.
func TestWatchLogReportsRotationFailure(t *testing.T) {
	dir := spiretest.TempDir(t)
	logPath := filepath.Join(dir, "test.log")

	rf, err := NewRotatableFile(logPath, RotationConfig{MaxSizeMB: new(1)})
	require.NoError(t, err)
	defer func() {
		_ = rf.Close()
	}()

	renameErr := errors.New("rename boom")
	rf.renameFunc = func(string, string) error { return renameErr }

	// Fill past the limit so the next write rotates, and fails.
	_, err = rf.Write([]byte(strings.Repeat("a", mebibyte)))
	require.NoError(t, err)
	_, err = rf.Write([]byte("trigger"))
	require.NoError(t, err, "the line is kept even though the rotation failed")

	logger, hook := newNullLogger()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		watchLog(ctx, logger, rf, nil, time.Millisecond)
	}()

	require.Eventually(t, func() bool {
		return len(hook.AllEntries()) > 0
	}, time.Second, 5*time.Millisecond, "the failure should be reported")

	cancel()
	<-done

	entry := hook.LastEntry()
	assert.Equal(t, logrus.ErrorLevel, entry.Level)
	assert.Equal(t, failedToRotateMsg, entry.Message)
	assert.ErrorIs(t, entry.Data[logrus.ErrorKey].(error), renameErr)

	// Draining clears it, so a single failure is not reported forever.
	assert.NoError(t, rf.TakeRotateError())
}

// A ReopenableFile has no rotation of its own, so there is nothing to drain.
func TestWatchLogIgnoresWritersWithoutRotation(t *testing.T) {
	dir := spiretest.TempDir(t)
	rf, err := NewReopenableFile(filepath.Join(dir, "test.log"))
	require.NoError(t, err)
	defer func() {
		_ = rf.Close()
	}()

	logger, hook := newNullLogger()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		watchLog(ctx, logger, rf, nil, time.Millisecond)
	}()

	time.Sleep(20 * time.Millisecond)
	cancel()
	<-done

	assert.Empty(t, hook.AllEntries())
}

func newNullLogger() (*Logger, *logrustest.Hook) {
	logrusLogger, hook := logrustest.NewNullLogger()
	return &Logger{Logger: logrusLogger, Closer: nopCloser{}}, hook
}
