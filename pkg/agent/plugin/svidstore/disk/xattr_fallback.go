// +build !linux
// +build !darwin
// +build !freebsd
// +build !netbsd

package disk

func setxattr(filePath, attr string, data []byte) error {
	// On unsupported systems, we just do nothing
	return nil
}

func getxattr(filePath, attr string, dest []byte) error {
	// On unsupported systems, we just do nothing
	return nil
}
