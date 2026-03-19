package disk

import "os"

// fileLock guards access to the keys file.
// It uses a separate lock file to coordinate access.
type fileLock struct {
	path string
	file *os.File
}

func newFileLock(path string) *fileLock {
	return &fileLock{path: path}
}
