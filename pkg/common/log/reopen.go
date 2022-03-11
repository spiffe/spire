package log

import (
	"fmt"
	"io"
	"os"
	"sync"
)

const (
	fileFlags = os.O_APPEND | os.O_CREATE | os.O_WRONLY
	fileMode  = 0640
)

var _ ReopenableWriteCloser = (*ReopenableFile)(nil)

type (
	// Reopener inspired by https://github.com/client9/reopen
	Reopener interface {
		Reopen() error
	}
	ReopenableWriteCloser interface {
		Reopener
		io.WriteCloser
	}
)

type (
	ReopenableFile struct {
		name      string
		f         *os.File
		closeFunc closeFunc
		mu        sync.Mutex
	}
	// closeFunc must be called while holding the lock. It is intended for
	// injecting errors under test.
	closeFunc func(*os.File) error
)

func NewReopenableFile(name string) (*ReopenableFile, error) {
	file, err := os.OpenFile(name, fileFlags, fileMode)
	if err != nil {
		return nil, err
	}
	closeFile := func(f *os.File) error {
		return f.Close()
	}
	return &ReopenableFile{
		name:      name,
		f:         file,
		closeFunc: closeFile,
	}, nil
}

func (r *ReopenableFile) Reopen() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	newFile, err := os.OpenFile(r.name, fileFlags, fileMode)
	if err != nil {
		return fmt.Errorf("unable to reopen %s: %w", r.name, err)
	}

	// Ignore errors closing old file descriptor since logger would be using
	// file descriptor we fail to close. This could leak file descriptors.
	_ = r.closeFunc(r.f)

	r.f = newFile
	return nil
}

func (r *ReopenableFile) Write(b []byte) (n int, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	return r.f.Write(b)
}

func (r *ReopenableFile) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	return r.f.Close()
}

// Name implements part of os.FileInfo without needing a lock on the
// underlying file.
func (r *ReopenableFile) Name() string {
	return r.name
}
