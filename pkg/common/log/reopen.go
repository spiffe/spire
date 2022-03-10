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
		Reopen(*Logger) error
	}
	ReopenableWriteCloser interface {
		Reopener
		io.WriteCloser
	}
)

type (
	ReopenableFile struct {
		name        string
		f           *os.File
		unsafeClose unsafeClose
		mu          sync.Mutex
	}
	// unsafeClose must be called while holding the lock
	unsafeClose func() error
)

func NewReopenableFile(name string) (*ReopenableFile, error) {
	file, err := os.OpenFile(name, fileFlags, fileMode)
	if err != nil {
		return nil, err
	}
	return &ReopenableFile{
		name:        name,
		f:           file,
		unsafeClose: file.Close,
	}, nil
}

func (r *ReopenableFile) Reopen(logger *Logger) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	newFile, err := os.OpenFile(r.name, fileFlags, fileMode)
	if err != nil {
		reopenErr := fmt.Errorf("unable to reopen %s: %w", r.name, err)
		// best effort to log error to old file descriptor
		go logger.Error(reopenErr)
		return reopenErr
	}

	// Ignore errors closing old file descriptor since logger would be using
	// file descriptor we fail to close. This could leak file descriptors.
	_ = r.unsafeClose()

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
