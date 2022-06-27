//go:build windows
// +build windows

package cli

import "github.com/sirupsen/logrus"

// SetUmask does nothing on Windows
func SetUmask(log logrus.FieldLogger) {
	// Nothing to do in this platform
}
