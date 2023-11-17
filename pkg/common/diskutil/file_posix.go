//go:build !windows

package diskutil

import (
	"os"
	"path/filepath"
)

const (
	fileModePrivate          = 0600
	fileModePubliclyReadable = 0644
)

// AtomicWritePrivateFile writes data out to a private file.
// It writes to a temp file first, fsyncs that file, then swaps the file in.
// It renames the file using MoveFileEx with  'MOVEFILE_WRITE_THROUGH',
// which waits until the file is synced to disk.
func AtomicWritePrivateFile(path string, data []byte) error {
	return atomicWrite(path, data, fileModePrivate)
}

// AtomicWritePubliclyReadableFile writes data out to a publicly readable file.
// It writes to a temp file first, fsyncs that file, then swaps the file in.
// It renames the file using MoveFileEx with  'MOVEFILE_WRITE_THROUGH',
// which waits until the file is synced to disk.
func AtomicWritePubliclyReadableFile(path string, data []byte) error {
	return atomicWrite(path, data, fileModePubliclyReadable)
}

func CreateDataDirectory(path string) error {
	return os.MkdirAll(path, 0755)
}

// WritePrivateFile writes data out to a private file. The file is created if it
// does not exist. If exists, it's overwritten.
func WritePrivateFile(path string, data []byte) error {
	return write(path, data, fileModePrivate, false)
}

// WritePubliclyReadableFile writes data out to a publicly readable file. The
// file is created if it does not exist. If exists, it's overwritten.
func WritePubliclyReadableFile(path string, data []byte) error {
	return write(path, data, fileModePubliclyReadable, false)
}

func atomicWrite(path string, data []byte, mode os.FileMode) error {
	tmpPath := path + ".tmp"
	if err := write(tmpPath, data, mode, true); err != nil {
		return err
	}

	return rename(tmpPath, path)
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

// write writes to a file in the specified path with the specified
// security descriptor using the provided data. The sync boolean
// argument is used to indicate whether flushing to disk is required
// or not.
func write(tmpPath string, data []byte, mode os.FileMode, sync bool) error {
	file, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}

	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}

	if sync {
		if err := file.Sync(); err != nil {
			file.Close()
			return err
		}
	}

	return file.Close()
}
