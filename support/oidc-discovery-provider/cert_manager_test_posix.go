//go:build !windows
// +build !windows

package main

import (
	"os"
)

var (
	certFilePath                = "/oidcServerCert.pem"
	keyFilePath                 = "/oidcServerKey.pem"
	fileDontExistMessage        = "no such file or directory"
	filePermissionDeniedMessage = "permission denied"
)

func writeFile(name string, data []byte) error {
	err := os.WriteFile(name, data, 0600)
	if err != nil {
		return err
	}
	_, err = os.Stat(name)
	return err
}

func removeFile(name string) error {
	return os.Remove(name)
}

func makeFileUnreadable(name string) error {
	return os.Chmod(name, 0200)
}

func makeFileReadable(name string, data []byte) error {
	err := os.Chmod(name, 0600)
	if err != nil {
		return err
	}
	return writeFile(name, data)
}
