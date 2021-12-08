//go:build windows
// +build windows

package diskutil

import (
	"os"
	"syscall"

	"golang.org/x/sys/windows"
)

const (
	movefileReplaceExisting = 0x1
	movefileWriteThrough    = 0x8
)

// AtomicWriteFile writes data out.  It writes to a temp file first, fsyncs that file,
// then swaps the file in. Rename file using a custom MoveFileEx that uses 'MOVEFILE_WRITE_THROUGH' witch waits until
// file is synced to disk.
func AtomicWriteFile(path string, data []byte, mode os.FileMode) error {
	tmpPath := path + ".tmp"
	if err := write(tmpPath, data, mode); err != nil {
		return err
	}

	return atomicRename(tmpPath, path)
}

func write(tmpPath string, data []byte, mode os.FileMode) error {
	file, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}

	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}

	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}

	return file.Close()
}

func atomicRename(oldPath, newPath string) error {
	if err := rename(oldPath, newPath); err != nil {
		return &os.LinkError{
			Op:  "rename",
			Old: oldPath,
			New: newPath,
			Err: err,
		}
	}

	return nil
}

func rename(oldPath, newPath string) error {
	from, err := syscall.UTF16PtrFromString(oldPath)
	if err != nil {
		return err
	}
	to, err := syscall.UTF16PtrFromString(newPath)
	if err != nil {
		return err
	}

	return windows.MoveFileEx(from, to, movefileReplaceExisting|movefileWriteThrough)
}
