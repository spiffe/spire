//go:build windows
// +build windows

package tpmutil

import (
	"io"

	"github.com/google/go-tpm/tpm2"
)

// openTPM open a channel to the TPM, Windows does not recieve a path.
func openTPM(paths ...string) (io.ReadWriteCloser, error) {
	return tpm2.OpenTPM()
}

// mayClose we must close always when running on windows
func mayClose(closer io.ReadWriteCloser) bool {
	return false
}
