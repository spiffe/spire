package cgroups

import (
	"io"
	"os"
)

// OSFileSystem implements FileSystem using the local disk
type OSFileSystem struct{}

func (OSFileSystem) Open(name string) (io.ReadCloser, error) {
	return os.Open(name)
}
