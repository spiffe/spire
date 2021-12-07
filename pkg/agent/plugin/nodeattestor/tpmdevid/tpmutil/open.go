//go:build !windows
// +build !windows

package tpmutil

import (
	"io"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

// openTPM open a channel to the TPM at the given path.
func openTPM(paths ...string) (io.ReadWriteCloser, error) {
	return tpm2.OpenTPM(paths[0])
}

// closeTPM EmulatorReadWriteCloser type does not need to be closed. It closes
// the connection after each Read() call. Closing it again results in
// an error.
func closeTPM(closer io.ReadWriteCloser) bool {
	_, ok := closer.(*tpmutil.EmulatorReadWriteCloser)
	return ok
}
