//go:build !windows

package signal

import "golang.org/x/sys/unix"

const (
	SIGINT  = unix.SIGINT
	SIGTERM = unix.SIGTERM
)
