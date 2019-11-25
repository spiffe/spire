package diskutil

import (
	"os"
	"path/filepath"
)

// AtomicWriteFile writes data out.  It writes to a temp file first, fsyncs that file,
// then swaps the file in.  os.Rename is an atomic operation, so this sequence avoids having
// a partially written file at the final location.  Finally, fsync is called on the directory
// to ensure the rename is persisted.
func AtomicWriteFile(path string, data []byte, mode os.FileMode) error {
	tmpPath := path + ".tmp"
	if err := write(tmpPath, data, mode); err != nil {
		return err
	}

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

	if err := dir.Close(); err != nil {
		return err
	}

	return nil
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

	if err := file.Close(); err != nil {
		return err
	}

	return nil
}
