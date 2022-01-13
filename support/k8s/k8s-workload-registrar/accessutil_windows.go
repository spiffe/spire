//go:build windows
// +build windows

package main

// certDirExistsAndReadOnly it is not verified on windows, and must be removed in future iterations
func dirExistsAndReadOnly(dirPath string) (bool, error) {
	return false, nil
}
