//go:build !windows

package log

import "os"

// openLogFile opens the log file for appending. A rename by an external
// rotator leaves this descriptor writing to the renamed file, which is what
// the SIGUSR2 reopen relies on.
func openLogFile(name string) (*os.File, error) {
	return os.OpenFile(name, fileFlags, fileMode)
}
