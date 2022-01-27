package log

import (
	"context"
	"io"
	"os"
	"os/signal"
	"sync"
	"syscall"
)

const _reopenSignal = syscall.SIGUSR2

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
	file, err := os.OpenFile(name, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
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

	if r.f != nil {
		if err := r.f.Close(); err != nil {
			return err
		}
		r.f = nil
	}
	newFile, err := os.OpenFile(r.name, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
	if err != nil {
		r.f = nil
		return err
	}
	r.f = newFile
	return nil
}

func (r *ReopenableFile) Write(p []byte) (n int, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	return r.f.Write(p)
}

func (r *ReopenableFile) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	return r.f.Close()
}

func ReopenOnSignal(ctx context.Context, rwc ReopenableWriteCloser) {
	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, _reopenSignal)
	reopenOnSignal(ctx, rwc, signalCh)
}

func reopenOnSignal(
	ctx context.Context,
	rwc ReopenableWriteCloser,
	signalCh chan os.Signal,
) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-signalCh:
			rwc.Reopen()
		}
	}
}
