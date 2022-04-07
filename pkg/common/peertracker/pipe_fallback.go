//go:build !windows
// +build !windows

package peertracker

import (
	"net"
)

func getCallerInfoFromPipeConn(conn net.Conn) (CallerInfo, error) {
	return CallerInfo{}, ErrUnsupportedPlatform
}
