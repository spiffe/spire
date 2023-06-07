//go:build !windows
// +build !windows

package main

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

var (
	certFilePath                = "/oidcServerCert.pem"
	keyFilePath                 = "/oidcServerKey.pem"
	fileDontExistMessage        = "no such file or directory"
	filePermissionDeniedMessage = "permission denied"
)

func writeFile(t *testing.T, name string, data []byte) {
	err := os.WriteFile(name, data, 0600)
	require.NoError(t, err)
	_, err = os.Stat(name)
	require.NoError(t, err)
}

func removeFile(t *testing.T, name string) {
	err := os.Remove(name)
	require.NoError(t, err)
}

func makeFileUnreadable(t *testing.T, name string) {
	err := os.Chmod(name, 0200)
	require.NoError(t, err)
}

func makeFileReadable(t *testing.T, name string, data []byte) {
	err := os.Chmod(name, 0600)
	require.NoError(t, err)
	writeFile(t, name, data)
}
