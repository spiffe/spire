//go:build windows
// +build windows

package cli

import "github.com/sirupsen/logrus"

const umaskSupported = false

// SetUmask does nothing on Windows
func SetUmask(log logrus.FieldLogger) {
	// Nothing to do in this platform
}
