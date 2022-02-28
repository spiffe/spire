//go:build !windows
// +build !windows

package peertracker

import (
	"net"
)

func getCallerInfoFromTCPConn(conn net.Conn) (CallerInfo, error) {
	return CallerInfo{}, ErrUnsupportedPlatform
}
