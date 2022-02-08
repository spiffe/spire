//go:build !linux && !darwin && !freebsd && !netbsd && !openbsd

package peertracker

import (
	"github.com/sirupsen/logrus"
)

func newTracker(log logrus.FieldLogger) (PeerTracker, error) {
	return nil, ErrUnsupportedPlatform
}
