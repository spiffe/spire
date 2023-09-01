//go:build !windows
// +build !windows

package peertracker

import (
	"net"
)

func getCallerInfoFromNamedPipeConn(net.Conn) (CallerInfo, error) {
	return CallerInfo{}, ErrUnsupportedPlatform
}
