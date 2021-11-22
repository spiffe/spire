//go:build windows
// +build windows

package diskutil

import (
	"os"
)

// AtomicWriteFile writes data out.  It writes to a temp file first, fsyncs that file,
// then swaps the file in.  os.Rename is an atomic operation, so this sequence avoids having
// a partially written file at the final location.
func AtomicWriteFile(path string, data []byte, mode os.FileMode) error {
	tmpPath := path + ".tmp"
	if err := write(tmpPath, data, mode); err != nil {
		return err
	}

	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}

	f, err := os.Open(path)
	if err != nil {
		return err
	}

	return f.Close()
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
