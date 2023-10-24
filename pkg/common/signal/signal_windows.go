//go:build windows

package signal

import (
	"golang.org/x/sys/windows"
)

const (
	SIGINT  = windows.SIGINT
	SIGTERM = windows.SIGTERM
)
