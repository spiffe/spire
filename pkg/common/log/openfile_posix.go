//go:build !windows

package log

import "os"

const (
	fileFlags = os.O_APPEND | os.O_CREATE | os.O_WRONLY
	fileMode  = 0640
)

// openLogFile opens the log file for appending.
func openLogFile(name string) (*os.File, error) {
	return os.OpenFile(name, fileFlags, fileMode)
}
