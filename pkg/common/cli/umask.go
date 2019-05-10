package cli

import "github.com/sirupsen/logrus"

// The umask for SPIRE processes should not allow write by group, or
// read/write/execute by everyone.
const minimumUmask = 0027

// SetUmask sets the minimumUmask.
func SetUmask(log logrus.FieldLogger) {
	if !umaskSupported {
		return
	}

	// Otherwise, make sure the current umask meets the minimum.
	currentUmask := setUmask(minimumUmask)
	if (currentUmask & minimumUmask) != minimumUmask {
		badUmask := currentUmask
		currentUmask |= minimumUmask
		log.Warnf("Current umask %#04o is too permissive; setting umask %#04o.", badUmask, currentUmask)
	}
	setUmask(currentUmask)
}
