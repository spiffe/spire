//go:build !windows

package cli

import (
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

// The umask for SPIRE processes should not allow write by group, or
// read/write/execute by everyone.
const minimumUmask = 0o027

// SetUmask sets the minimumUmask.
func SetUmask(log logrus.FieldLogger) {
	// Otherwise, make sure the current umask meets the minimum.
	currentUmask := unix.Umask(minimumUmask)
	if (currentUmask & minimumUmask) != minimumUmask {
		badUmask := currentUmask
		currentUmask |= minimumUmask
		log.Warnf("Current umask %#04o is too permissive; setting umask %#04o", badUmask, currentUmask)
	}
	_ = unix.Umask(currentUmask)
}
