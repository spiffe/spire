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
		r.f = nil
		return err
	}

	if r.f != nil {
		if err := r.f.Close(); err != nil {
			return err
		}
		r.f = nil
	}

	r.f = newFile
	return nil
}

func (r *ReopenableFile) Write(b []byte) (n int, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.f == nil {
		return 0, fmt.Errorf("%s is nil", r.name)
	}

	return r.f.Write(b)
}

func (r *ReopenableFile) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.f == nil {
		return fmt.Errorf("%s is nil", r.name)
	}

	return r.f.Close()
}

// Name implements part of os.FileInfo without needing a lock on the
// underlying file.
func (r *ReopenableFile) Name() string {
	return r.name
}
