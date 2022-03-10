package log

import (
	"context"
	"testing"
)

var (
	_ ReopenableWriteCloser = (*fakeReopenableFile)(nil)
)

type fakeReopenableFile struct {
	rf        *ReopenableFile
	t         *testing.T
	reopenErr error
	closeErr  error
	cancel    context.CancelFunc
}

func (f *fakeReopenableFile) Reopen(logger *Logger) error {
	f.t.Log("entering Reopen")
	var err error
	if f.rf != nil {
		f.t.Log("calling f.rf.Reopen")
		err = f.rf.Reopen(logger)
	}
	if f.reopenErr != nil {
		err = f.reopenErr
	}
	if f.cancel != nil {
		f.cancel()
	}
	f.t.Log(err)
	return err
}

func (f *fakeReopenableFile) Write(b []byte) (n int, err error) {
	if f.rf != nil {
		return f.rf.Write(b)
	}
	return 0, nil
}

func (f *fakeReopenableFile) Close() error {
	if f.rf != nil {
		return f.rf.Close()
	}
	return nil
}

func (f *fakeReopenableFile) unsafeClose() error {
	f.t.Log("entering unsafeClose()")
	var err error
	if f.closeErr != nil {
		err = f.closeErr
	}
	f.t.Log(err)
	return err
}
