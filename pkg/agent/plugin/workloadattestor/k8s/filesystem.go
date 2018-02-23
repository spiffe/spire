//go:generate mockgen -source=$GOFILE -destination=../../../test/mock/common/filesystem/filesystem.go -package=filesystem_mock

package k8s

import (
	"os"
)

type fileSystem interface {
	Open(name string) (*os.File, error)
}

type osFS struct{}

// osFS implements fileSystem using the local disk
func (osFS) Open(name string) (*os.File, error) {
	return os.Open(name)
}
