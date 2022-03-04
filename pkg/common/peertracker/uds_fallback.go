//go:build !linux && !darwin && !freebsd && !netbsd && !openbsd
// +build !linux,!darwin,!freebsd,!netbsd,!openbsd

package peertracker

func getCallerInfoFromFileDescriptor(fd uintptr) (CallerInfo, error) {
	return CallerInfo{}, ErrUnsupportedPlatform
}
