//go:build windows

package cli

import "github.com/sirupsen/logrus"

// SetUmask does nothing on Windows
func SetUmask(logrus.FieldLogger) {
	// Nothing to do in this platform
}
