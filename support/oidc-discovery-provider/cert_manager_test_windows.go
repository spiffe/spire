//go:build windows
// +build windows

package main

import (
	"os"

	"golang.org/x/sys/windows"
)

var (
	certFilePath                = "\\oidcServerCert.pem"
	keyFilePath                 = "\\oidcServerKey.pem"
	fileDontExistMessage        = "The system cannot find the file specified."
	filePermissionDeniedMessage = "Access is denied."
)

func writeFile(name string, data []byte) error {
	handle, err := windows.Open(name, os.O_RDWR|os.O_CREATE, 0666)
	defer windows.Close(handle)
	if err != nil {
		return err
	}
	_, err = windows.Write(handle, data)
	if err != nil {
		return err
	}
	return nil
}

func removeFile(name string) error {
	return windows.DeleteFile(windows.StringToUTF16Ptr(name))
}

func makeFileUnreadable(name string) error {
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

	if err != nil {
		return err
	}

	// this SDDL code denies generic read access to the owner of the file
	sd, err := windows.SecurityDescriptorFromString("D:(D;OICI;GR;;;OW)")
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}

	err = windows.SetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
	if err != nil {
		return err
	}

	return nil
}

func makeFileReadable(name string, data []byte) error {
	err := removeFile(name)
	if err != nil {
		return err
	}
	return writeFile(name, data)
}
