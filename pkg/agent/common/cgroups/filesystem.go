package cgroups

import "os"

// OSFileSystem implements FileSystem using the local disk
type OSFileSystem struct{}

func (OSFileSystem) Open(name string) (*os.File, error) {
	return os.Open(name)
}
