//go:build !linux && !darwin && !freebsd && !netbsd && !openbsd
// +build !linux,!darwin,!freebsd,!netbsd,!openbsd

package peertracker

func getCallerInfoFromFileDescriptor(uintptr) (CallerInfo, error) {
	return CallerInfo{}, ErrUnsupportedPlatform
}
