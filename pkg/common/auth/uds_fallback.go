// +build !linux
// +build !darwin
// +build !freebsd
// +build !netbsd
// +build !openbsd

package auth

func getPeerPID(fd uintptr) (pid int32, err error) {
	return 0, ErrUnsupportedPlatform
}
