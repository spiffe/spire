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

// fileDeleted reports whether the file behind f has been deleted. POSIX frees
// the name as soon as the file is unlinked, so a reopen there always gets a new
// file and never has to ask.
func fileDeleted(*os.File) bool {
	return false
}
