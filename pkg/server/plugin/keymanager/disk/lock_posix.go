//go:build !windows

package disk

import (
	"os"
	"syscall"
)

// Lock acquires an exclusive lock on the file.
// It blocks until the lock is acquired.
func (l *fileLock) Lock() error {
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	l.file = f

	// LOCK_EX = Exclusive lock
	// This blocks until the lock is available.
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		l.file.Close()
		l.file = nil
		return err
	}
	return nil
}

// Unlock releases the lock and closes the file.
func (l *fileLock) Unlock() error {
	if l.file == nil {
		return nil
	}
	defer func() {
		l.file.Close()
		l.file = nil
	}()

	// LOCK_UN = Unlock
	return syscall.Flock(int(l.file.Fd()), syscall.LOCK_UN)
}
