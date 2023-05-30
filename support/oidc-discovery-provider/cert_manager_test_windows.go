//go:build windows
// +build windows

package main

import (
	"fmt"

	"golang.org/x/sys/windows"
)

var (
	certFilePath                = "\\oidcServerCert.pem"
	keyFilePath                 = "\\oidcServerKey.pem"
	fileDontExistMessage        = "The system cannot find the file specified."
	filePermissionDeniedMessage = "Access is denied."
)

func writeFile(name string, data []byte) error {
	handle, err := windows.CreateFile(windows.StringToUTF16Ptr(name),
		windows.GENERIC_ALL,
		0,
		nil,
		windows.CREATE_ALWAYS,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		return err
	}
	_, err = windows.Write(handle, data)
	if err != nil {
		return err
	}
	return windows.Close(handle)
}

func removeFile(name string) error {
	return windows.DeleteFile(windows.StringToUTF16Ptr(name))
}

func makeFileUnreadable(name string) error {
	handle, err := windows.CreateFile(windows.StringToUTF16Ptr(name),
		windows.GENERIC_ALL,
		0,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)

	if err != nil {
		return err
	}

	// this SDDL code denies the owner of the object from reading it
	sd, err := windows.SecurityDescriptorFromString(fmt.Sprintf("D:(D;OICI;GR;;;OW)(A;OICI;FA;;;WD)"))
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

	return windows.Close(handle)
}

func makeFileReadable(name string, data []byte) error {
	err := removeFile(name)
	if err != nil {
		return err
	}
	return writeFile(name, data)
}
