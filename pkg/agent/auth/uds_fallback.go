// +build !linux

package auth

import "net"

func FromUDSConn(conn net.Conn) CallerInfo {
	var info CallerInfo
	info.Err = ErrUnsupportedPlatform
	return info
}
