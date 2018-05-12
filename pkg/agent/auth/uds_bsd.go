// +build darwin freebsd netbsd openbsd

package auth

import (
	"net"

	"golang.org/x/sys/unix"
)

func FromUDSConn(conn net.Conn) CallerInfo {
	var info CallerInfo

	uconn, ok := conn.(*net.UnixConn)
	if !ok {
		info.Err = ErrInvalidConnection
		return info
	}

	file, err := uconn.File()
	if err != nil {
		info.Err = err
		return info
	}
	defer file.Close()

	result, err := unix.GetsockoptInt(int(file.Fd()), 0, 0x002) //getsockopt(fd, SOL_LOCAL, LOCAL_PEERPID)
	if err != nil {
		info.Err = err
		return info
	}

	info.Addr = uconn.RemoteAddr()
	info.PID = int32(result)
	return info
}
