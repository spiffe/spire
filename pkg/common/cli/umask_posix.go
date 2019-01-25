package cli

import "syscall"

const umaskSupported = true

func setUmask(umask int) int {
	return syscall.Umask(umask)
}
