// +build !linux
// +build !darwin
// +build !freebsd
// +build !netbsd
// +build !openbsd

package peertracker

func newTracker() (PeerTracker, error) {
	return nil, ErrUnsupportedPlatform
}
