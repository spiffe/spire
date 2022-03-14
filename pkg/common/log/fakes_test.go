//go:build !windows

package log

import (
	"context"
	"os"
	"testing"
)

var (
	_ ReopenableWriteCloser = (*fakeReopenableFile)(nil)
)

type fakeReopenableFile struct {
	t         *testing.T
	rf        *ReopenableFile
	reopenErr error
	closeErr  error
	cancel    context.CancelFunc
}

func (f *fakeReopenableFile) Reopen() error {
	f.t.Helper()
	f.t.Log("entering Reopen")
	var err error
	if f.rf != nil {
		f.t.Log("calling f.rf.Reopen")
		err = f.rf.Reopen()
	}
	if f.reopenErr != nil {
		err = f.reopenErr
	}
	if f.cancel != nil {
		f.cancel()
	}
	f.t.Logf("error in Reopen: %v", err)
	return err
}

func (f *fakeReopenableFile) Write(b []byte) (n int, err error) {
	f.t.Helper()
	if f.rf != nil {
		return f.rf.Write(b)
	}
	return 0, nil
}

func (f *fakeReopenableFile) Close() error {
	f.t.Helper()
	if f.rf != nil {
		return f.rf.Close()
	}
	return nil
}

func (f *fakeReopenableFile) fakeCloseError(fake *os.File) error {
	f.t.Helper()
	f.t.Log("entering closeFake()")
	return f.closeErr
}
