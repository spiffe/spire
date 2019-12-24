// +build darwin freebsd netbsd openbsd

package peertracker

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"syscall"
	"time"
)

var (
	safetyDelay = 250 * time.Millisecond
)

type bsdTracker struct {
	closer      func()
	ctx         context.Context
	kqfd        int
	mtx         sync.Mutex
	watchedPIDs map[int]chan struct{}
}

func newTracker() (*bsdTracker, error) {
	kqfd, err := syscall.Kqueue()
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())
	tracker := &bsdTracker{
		closer:      cancel,
		ctx:         ctx,
		kqfd:        kqfd,
		watchedPIDs: make(map[int]chan struct{}),
	}

	go tracker.receiveKevents(kqfd)

	return tracker, nil
}

func (b *bsdTracker) Close() {
	b.mtx.Lock()
	defer b.mtx.Unlock()

	// Be sure to cancel the context before closing the
	// kqueue file descriptor so the goroutine watching it
	// will know that we are shutting down.
	b.closer()
	syscall.Close(b.kqfd)
}

func (b *bsdTracker) NewWatcher(info CallerInfo) (Watcher, error) {
	// If PID == 0, something is wrong...
	if info.PID == 0 {
		return nil, errors.New("could not resolve caller information")
	}

	if b.ctx.Err() != nil {
		return nil, errors.New("tracker has been closed")
	}

	b.mtx.Lock()
	defer b.mtx.Unlock()

	pid := int(info.PID)

	done, ok := b.watchedPIDs[pid]
	if !ok {
		err := b.addKeventForWatcher(pid)
		if err != nil {
			return nil, fmt.Errorf("could not create watcher: %v", err)
		}

		done = make(chan struct{})
		b.watchedPIDs[pid] = done
	}

	return newBSDWatcher(info, done), nil
}

func (b *bsdTracker) addKeventForWatcher(pid int) error {
	kevent := syscall.Kevent_t{}
	flags := syscall.EV_ADD | syscall.EV_RECEIPT | syscall.EV_ONESHOT
	syscall.SetKevent(&kevent, pid, syscall.EVFILT_PROC, flags)

	kevent.Fflags = syscall.NOTE_EXIT

	kevents := []syscall.Kevent_t{kevent}
	_, err := syscall.Kevent(b.kqfd, kevents, nil, nil)
	return err
}

func (b *bsdTracker) receiveKevents(kqfd int) {
	for {
		receive := make([]syscall.Kevent_t, 5)
		num, err := syscall.Kevent(kqfd, nil, receive, nil)
		if err != nil {
			// KQUEUE(2) outlines the conditions under which the Kevent call
			// can return an error - they are as follows:
			//
			// EACCESS: The process does not have permission to register a filter.
			// EFAULT: There was an error reading or writing the kevent or kevent64_s structure.
			// EBADF: The specified descriptor is invalid.
			// EINTR: A signal was delivered before the timeout expired and before any events were
			//        placed on the kqueue for return.
			// EINVAL: The specified time limit or filter is invalid.
			// ENOENT: The event could not be found to be modified or deleted.
			// ENOMEM: No memory was available to register the event.
			// ESRCH: The specified process to attach to does not exist.
			//
			// Given our usage, the only error that seems possible is EBADF during shutdown.
			// If we encounter any other error, we really have no way to recover. This will cause
			// all subsequent workload attestations to fail open. After much deliberation, it is
			// decided that the safest thing to do is to panic and allow supervision to step in.
			// If this is actually encountered in the wild, we can examine the conditions and try
			// to do something more intelligent. For now, we will just check to see if we are
			// shutting down.
			if b.ctx.Err() != nil {
				// Don't panic, we're just shutting down
				return
			}

			if err == syscall.EINTR {
				continue
			}

			panicMsg := fmt.Sprintf("unrecoverable error while reading from kqueue: %v", err)
			panic(panicMsg)
		}

		b.mtx.Lock()
		for _, kevent := range receive[:num] {
			if kevent.Filter == syscall.EVFILT_PROC && (kevent.Fflags&syscall.NOTE_EXIT) > 0 {
				pid := int(kevent.Ident)
				done, ok := b.watchedPIDs[pid]
				if ok {
					close(done)
					delete(b.watchedPIDs, pid)
				}
			}
		}
		b.mtx.Unlock()
	}
}

type bsdWatcher struct {
	closed bool
	done   <-chan struct{}
	mtx    sync.Mutex
	pid    int32
}

func newBSDWatcher(info CallerInfo, done <-chan struct{}) *bsdWatcher {
	return &bsdWatcher{
		done: done,
		pid:  info.PID,
	}
}

func (b *bsdWatcher) Close() {
	// For simplicity, don't bother cleaning up after ourselves
	// The map entry will be reaped when the process exits
	//
	// Other watchers are unable to track after closed (unlike
	// this one), so to provide consistent behavior, set the closed
	// bit and return an error on subsequent IsAlive() calls
	b.mtx.Lock()
	defer b.mtx.Unlock()
	b.closed = true
}

func (b *bsdWatcher) IsAlive() error {
	b.mtx.Lock()
	if b.closed {
		b.mtx.Unlock()
		return errors.New("caller is no longer being watched")
	}
	b.mtx.Unlock()

	// Using kqueue/kevent means we are relying on an asynchronous notification
	// system for exit detection. Delays can be incurred on either side: in our
	// kevent consumer or in the kernel. Typically, IsAlive() is called following
	// workload attestation which can take hundreds of milliseconds, so in practice
	// we will probably have been notified of an exit by now if it occurred prior to
	// or during the attestation process.
	//
	// As an extra safety precaution, artificially delay our answer to IsAlive() in
	// a blind attempt to allow "enough" time to pass for us to learn of the
	// potential exit event.
	time.Sleep(safetyDelay)

	select {
	case <-b.done:
		return errors.New("caller exit detected via kevent notification")
	default:
		return nil
	}
}

func (b *bsdWatcher) PID() int32 {
	return b.pid
}
