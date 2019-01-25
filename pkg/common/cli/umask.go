package cli

import "github.com/sirupsen/logrus"

// The umask for SPIRE processes should not allow write by group, or
// read/write/execute by everyone.
const minimumUmask = 0027

// SetUmask sets the desired umask if desiredUmask is >= 0. The desired umask
// is upgraded to include the minimumUmask bits if it is weaker. If
// desiredUmask is < 0, then the current umask is upgraded to include the
// minimumUmask bits, if necessary.
func SetUmask(log logrus.FieldLogger, desiredUmask int) {
	if desiredUmask >= 0 {
		log.Warnf("Setting umask %#04o via configuration (deprecated)", desiredUmask)
		if !umaskSupported {
			log.Warn("Umask not supported on this platform.")
			return
		}
		if (desiredUmask & minimumUmask) != minimumUmask {
			badUmask := desiredUmask
			desiredUmask |= minimumUmask
			log.Warnf("Desired umask %#04o is too permissive; setting umask %#04o.", badUmask, desiredUmask)
		}
		setUmask(desiredUmask)
		return
	}

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
