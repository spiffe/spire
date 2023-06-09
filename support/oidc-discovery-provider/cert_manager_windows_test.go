//go:build windows
// +build windows

package main

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

var (
	certFilePath                = "\\oidcServerCert.pem"
	keyFilePath                 = "\\oidcServerKey.pem"
	fileDontExistMessage        = "The system cannot find the file specified."
	filePermissionDeniedMessage = "Access is denied."
)

func writeFile(t *testing.T, name string, data []byte) {
	err := os.WriteFile(name, data, 0600)
	require.NoError(t, err)
}

func removeFile(t *testing.T, name string) {
	err := os.Remove(name)
	require.NoError(t, err)
}

func makeFileUnreadable(t *testing.T, name string) {
	ptr := windows.StringToUTF16Ptr(name)
	handle, err := windows.CreateFile(
		ptr,
		windows.READ_CONTROL|windows.WRITE_DAC,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL,
		0)

	defer windows.Close(handle)

	require.NoError(t, err)

	// This SDDL code denies generic read access to the owner of the file
	sd, err := windows.SecurityDescriptorFromString("D:(D;OICI;GR;;;OW)")
	require.NoError(t, err)

	dacl, _, err := sd.DACL()
	require.NoError(t, err)

	err = windows.SetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
	require.NoError(t, err)
}

func makeFileReadable(t *testing.T, name string, data []byte) {
	removeFile(t, name)
	writeFile(t, name, data)
}
