//go:build !windows

package cli

import (
	"syscall"

	"github.com/sirupsen/logrus"
)

// The umask for SPIRE processes should not allow write by group, or
// read/write/execute by everyone.
const minimumUmask = 0027

// SetUmask sets the minimumUmask.
func SetUmask(log logrus.FieldLogger) {
	// Otherwise, make sure the current umask meets the minimum.
	currentUmask := syscall.Umask(minimumUmask)
	if (currentUmask & minimumUmask) != minimumUmask {
		badUmask := currentUmask
		currentUmask |= minimumUmask
		log.Warnf("Current umask %#04o is too permissive; setting umask %#04o", badUmask, currentUmask)
	}
	_ = syscall.Umask(currentUmask)
}
