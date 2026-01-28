//go:build windows

package disk

import (
	"os"

	"golang.org/x/sys/windows"
)

// Lock acquires an exclusive lock on the file.
// It blocks until the lock is acquired.
func (l *fileLock) Lock() error {
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	l.file = f

	h := windows.Handle(f.Fd())
	var overlapped windows.Overlapped

	// Lock the entire file (max uint32 for low and high).
	// LOCKFILE_EXCLUSIVE_LOCK ensures exclusive access.
	// No LOCKFILE_FAIL_IMMEDIATELY means it blocks.
	const reserved = 0
	if err := windows.LockFileEx(h, windows.LOCKFILE_EXCLUSIVE_LOCK, reserved, 0xFFFFFFFF, 0xFFFFFFFF, &overlapped); err != nil {
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

	h := windows.Handle(l.file.Fd())
	var overlapped windows.Overlapped
	const reserved = 0
	return windows.UnlockFileEx(h, reserved, 0xFFFFFFFF, 0xFFFFFFFF, &overlapped)
}
