// +build !linux
// +build !darwin
// +build !freebsd
// +build !netbsd
// +build !openbsd

package peertracker

import (
	"github.com/sirupsen/logrus"
)

func newTracker(log logrus.FieldLogger) (PeerTracker, error) {
	return nil, ErrUnsupportedPlatform
}
