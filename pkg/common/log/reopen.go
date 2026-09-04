package log

import (
	"fmt"
	"io"
	"os"
	"sync"
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
	file, err := openLogFile(name)
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

	newFile, err := openLogFile(r.name)
	if err != nil && fileDeleted(r.f) {
		// An external tool deleted the file while we held it open. Windows
		// keeps the name until the last handle closes, so letting go of ours is
		// the only way to get a new file at that path. Should the retry fail
		// too, there is no descriptor left until the next reopen, and the
		// error returned here has nowhere to be written on a Windows service.
		r.releaseFile()
		newFile, err = openLogFile(r.name)
	}
	if err != nil {
		return fmt.Errorf("unable to reopen %s: %w", r.name, err)
	}

	r.releaseFile()
	r.f = newFile
	return nil
}

// releaseFile closes the current file, if any, and forgets it. It must be
// called while holding the lock. Errors are ignored since the logger would
// otherwise keep using a descriptor we failed to close, which could leak file
// descriptors.
func (r *ReopenableFile) releaseFile() {
	if r.f == nil {
		return
	}
	_ = r.closeFunc(r.f)
	r.f = nil
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
