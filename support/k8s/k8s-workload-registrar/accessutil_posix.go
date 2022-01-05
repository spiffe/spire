//go:build !windows
// +build !windows

package main

import (
	"errors"

	"golang.org/x/sys/unix"
)

// dirExistsAndReadOnly verify if folder is readonly and exists. It must be removed in future iterations
func dirExistsAndReadOnly(dirPath string) (bool, error) {
	err := unix.Access(dirPath, unix.W_OK)
	switch {
	case err == nil, errors.Is(err, unix.ENOENT):
		return false, nil
	case errors.Is(err, unix.EROFS):
		return true, nil
	default:
		return false, err
	}
}
