//go:build !linux && !darwin && !freebsd && !netbsd && !openbsd

package peertracker

func getCallerInfo(fd uintptr) (CallerInfo, error) {
	return CallerInfo{}, ErrUnsupportedPlatform
}
