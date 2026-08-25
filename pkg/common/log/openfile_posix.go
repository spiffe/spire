//go:build !windows

package log

import "os"

// openLogFile opens the log file for appending.
func openLogFile(name string) (*os.File, error) {
	return os.OpenFile(name, fileFlags, fileMode)
}
