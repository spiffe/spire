package errorutil

import (
	"syscall"
)

func IsSIGINTOrSIGTERMError(err error) bool {
	switch err.Error() {
	case syscall.SIGINT.String() + " signal received":
		return true
	case syscall.SIGTERM.String() + " signal received":
		return true
	default:
		return false
	}
}
