package log

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeReopener struct {
	called chan struct{}
	count  atomic.Int64
	err    error
}

// Reopen never blocks, so an unexpected extra call surfaces as a count
// mismatch rather than a hung test.
func (f *fakeReopener) Reopen() error {
	f.count.Add(1)
	select {
	case f.called <- struct{}{}:
	default:
	}
	return f.err
}

func drainReopenRequests(t *testing.T) {
	t.Helper()
	for {
		select {
		case <-reopenRequests:
		default:
			return
		}
	}
}

func TestRequestReopenCoalesces(t *testing.T) {
	drainReopenRequests(t)
	t.Cleanup(func() { drainReopenRequests(t) })

	// More requests than the buffer holds. None of them may block, since the
	// service control handler has to return promptly.
	for range 10 {
		RequestReopen()
	}

	select {
	case <-reopenRequests:
	default:
		t.Fatal("expected a pending reopen request")
	}
	select {
	case <-reopenRequests:
		t.Fatal("requests should coalesce rather than queue")
	default:
	}
}

func TestWatchLogReopensOnRequest(t *testing.T) {
	logrusLogger, logHook := test.NewNullLogger()
	logger := &Logger{Logger: logrusLogger}

	for _, tt := range []struct {
		desc           string
		reopenErr      error
		wantLogEntries []spiretest.LogEntry
	}{
		{
			desc:           "reopen succeeds",
			wantLogEntries: []spiretest.LogEntry(nil),
		},
		{
			desc:      "reopen fails",
			reopenErr: errors.New("some error"),
			wantLogEntries: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: failedToReopenMsg,
					Data:    logrus.Fields{logrus.ErrorKey: "some error"},
				},
			},
		},
	} {
		t.Run(tt.desc, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			reopener := &fakeReopener{called: make(chan struct{}, 1), err: tt.reopenErr}
			requests := make(chan struct{}, 1)
			returned := make(chan struct{})
			go func() {
				defer close(returned)
				watchLog(ctx, logger, reopener, nil, requests, rotateErrorDrain{})
			}()

			requests <- struct{}{}
			select {
			case <-reopener.called:
			case <-time.After(time.Minute):
				t.Fatal("timed out waiting for Reopen to be called")
			}

			cancel()
			select {
			case <-returned:
			case <-time.After(time.Minute):
				t.Fatal("timed out waiting for the loop to return")
			}

			assert.Equal(t, int64(1), reopener.count.Load(), "one request should reopen once")
			spiretest.AssertLogs(t, logHook.AllEntries(), tt.wantLogEntries)
			logHook.Reset()
		})
	}
}

// An external tool moving the log aside is the flow logrotate uses on POSIX,
// and it works on Windows only because the log file is opened with
// FILE_SHARE_DELETE.
func TestReopenableFileReopenAfterExternalRename(t *testing.T) {
	dir := spiretest.TempDir(t)
	logPath := filepath.Join(dir, "test.log")
	rotatedPath := logPath + ".1"

	rf, err := NewReopenableFile(logPath)
	require.NoError(t, err)
	t.Cleanup(func() { _ = rf.Close() })

	_, err = rf.Write([]byte("before"))
	require.NoError(t, err)

	require.NoError(t, os.Rename(logPath, rotatedPath))
	require.NoError(t, rf.Reopen())

	_, err = rf.Write([]byte("after"))
	require.NoError(t, err)

	assert.Equal(t, "before", readFileString(t, rotatedPath))
	assert.Equal(t, "after", readFileString(t, logPath))
}

// Deleting rather than renaming leaves the name claimed until every handle to
// it is closed, so reopening has to let go of the old descriptor first.
func TestReopenableFileReopenAfterExternalDelete(t *testing.T) {
	dir := spiretest.TempDir(t)
	logPath := filepath.Join(dir, "test.log")

	rf, err := NewReopenableFile(logPath)
	require.NoError(t, err)
	t.Cleanup(func() { _ = rf.Close() })

	_, err = rf.Write([]byte("before"))
	require.NoError(t, err)

	require.NoError(t, os.Remove(logPath))
	require.NoError(t, rf.Reopen(), "reopen should recover from a deleted log file")

	_, err = rf.Write([]byte("after"))
	require.NoError(t, err)
	assert.Equal(t, "after", readFileString(t, logPath))
}

func readFileString(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	return string(b)
}
