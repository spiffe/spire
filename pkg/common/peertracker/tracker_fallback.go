//go:build !linux && !darwin && !freebsd && !netbsd && !openbsd && !windows

package peertracker

import (
	"github.com/sirupsen/logrus"
)

func newTracker(_ logrus.FieldLogger) (PeerTracker, error) {
	return nil, ErrUnsupportedPlatform
}
