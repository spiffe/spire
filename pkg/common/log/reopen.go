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

// Reopener inspired by https://github.com/client9/reopen
type Reopener interface {
	Reopen() error
}

type ReopenableWriteCloser interface {
	Reopener
	io.WriteCloser
}

type ReopenableFile struct {
	name string
	f    *os.File
	mu   sync.Mutex
}

func NewReopenableFile(name string) (*ReopenableFile, error) {
	file, err := os.OpenFile(name, fileFlags, fileMode)
	if err != nil {
		return nil, err
	}
	return &ReopenableFile{
		name: name,
		f:    file,
	}, nil
}

func (r *ReopenableFile) Reopen() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	newFile, err := os.OpenFile(r.name, fileFlags, fileMode)
	if err != nil {
		reopenErr := fmt.Errorf("unable to reopen %s: %w", r.name, err)
		// best effort to log error to old file descriptor
		if _, err := r.f.WriteString(reopenErr.Error()); err != nil {
			return fmt.Errorf("unable to log %q: %w", reopenErr.Error(), err)
		}
		return reopenErr
	}

	if err := r.f.Close(); err != nil {
		closeErr := fmt.Errorf("unable to close old %s: %w", r.name, err)
		// attempt to close newFile to prevent file descriptor leak
		if err := newFile.Close(); err != nil {
			leakErr := fmt.Errorf(
				"file descriptor leak closing new %s: %v: %w",
				r.name, err.Error(), closeErr,
			)
			closeErr = leakErr
		}
		// best effort to log error to old file descriptor
		if _, err := r.f.WriteString(closeErr.Error()); err != nil {
			return fmt.Errorf("unable to log %q: %w", closeErr.Error(), err)
		}
		return closeErr
	}

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
