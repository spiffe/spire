//go:build !windows
// +build !windows

package diskutil

import (
	"os"
	"path/filepath"
)

// AtomicWritePrivateFile writes data out.  It writes to a temp file first, fsyncs that file,
// then swaps the file in.  os.Rename is an atomic operation, so this sequence avoids having
// a partially written file at the final location.  Finally, fsync is called on the directory
// to ensure the rename is persisted.
func AtomicWritePrivateFile(path string, data []byte) error {
	tmpPath := path + ".tmp"
	if err := write(tmpPath, data, 0600); err != nil {
		return err
	}

	return rename(tmpPath, path)
}

// AtomicWritePubliclyReadableFile writes data out.  It writes to a temp file first, fsyncs that file,
// then swaps the file in.  os.Rename is an atomic operation, so this sequence avoids having
// a partially written file at the final location.  Finally, fsync is called on the directory
// to ensure the rename is persisted.
func AtomicWritePubliclyReadableFile(path string, data []byte) error {
	tmpPath := path + ".tmp"
	if err := write(tmpPath, data, 0644); err != nil {
		return err
	}

	return rename(tmpPath, path)
}

func CreateDataDirectory(path string) error {
	return os.MkdirAll(path, 0755)
}

func rename(tmpPath, path string) error {
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}

	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}

	if err := dir.Sync(); err != nil {
		dir.Close()
		return err
	}

	return dir.Close()
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
