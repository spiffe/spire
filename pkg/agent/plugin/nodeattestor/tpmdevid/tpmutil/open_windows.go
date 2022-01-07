//go:build windows
// +build windows

package tpmutil

import (
	"errors"
	"io"

	"github.com/google/go-tpm/tpm2"
)

// openTPM open a channel to the TPM, Windows does not receive a path.
func openTPM(paths ...string) (io.ReadWriteCloser, error) {
	if len(paths) != 0 && paths[0] != "" {
		return nil, errors.New("open tpm does not allows to set a device path")
	}

	return tpm2.OpenTPM()
}

// closeTPM we must close always when running on windows
func closeTPM(closer io.ReadWriteCloser) bool {
	return true
}
