// +build !linux
// +build !darwin
// +build !freebsd
// +build !netbsd
// +build !openbsd

package peertracker

func getCallerInfo(fd uintptr) (CallerInfo, error) {
	return CallerInfo{}, ErrUnsupportedPlatform
}
