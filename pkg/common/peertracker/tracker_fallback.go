//go:build !linux && !darwin && !freebsd && !netbsd && !openbsd && !windows
// +build !linux,!darwin,!freebsd,!netbsd,!openbsd,!windows

package peertracker

import (
	"github.com/sirupsen/logrus"
)

func newTracker(log logrus.FieldLogger) (PeerTracker, error) {
	return nil, ErrUnsupportedPlatform
}
