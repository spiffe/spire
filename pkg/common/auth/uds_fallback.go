// +build !linux
// +build !darwin
// +build !freebsd
// +build !netbsd
// +build !openbsd

package auth

func getPeerPID(fd int) (pid int, err error) {
	return 0, ErrUnsupportedPlatform
}
