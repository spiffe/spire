// +build !linux

package uds

import "net"

func FromUDSConn(conn net.Conn) CallerInfo {
	var info CallerInfo
	info.Err = ErrNotSupported
	return info
}
