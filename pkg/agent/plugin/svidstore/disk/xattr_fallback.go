// +build !linux
// +build !darwin

package disk

import "errors"

func setxattr(filePath, attr string, data []byte) error {
	// On unsupported systems, we just do nothing
	return nil

func getxattr(filePath, attr string, dest []byte) (err error) {
	// On unsupported systems, we just do nothing
	return nil
}
