//go:build linux || darwin
// +build linux darwin

package disk

import (
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

func setxattr(filePath, attr string, data []byte) error {
	if err := unix.Setxattr(filePath, attr, data, 0); errors.Is(err, unix.ENOTSUP) {
		return fmt.Errorf("error setting extended attribute: %w", err)
	}
	return nil
}

func getxattr(filePath, attr string, dest []byte) (err error) {
	if _, err = unix.Getxattr(filePath, attr, dest); errors.Is(err, unix.ENOTSUP) {
		return fmt.Errorf("error getting extended attribute: %w", err)
	}
	return nil
}
