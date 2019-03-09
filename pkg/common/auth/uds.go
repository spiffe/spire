package auth

import (
	"net"
	"syscall"
)

func FromUDSConn(conn net.Conn) CallerInfo {
	var info CallerInfo

	sysconn, ok := conn.(syscall.Conn)
	if !ok {
		info.Err = ErrInvalidConnection
		return info
	}

	rawconn, err := sysconn.SyscallConn()
	if err != nil {
		info.Err = ErrInvalidConnection
		return info
	}

	var result int32
	controlErr := rawconn.Control(func(fd uintptr) {
		result, err = getPeerPID(fd)
	})

	if controlErr != nil || err != nil {
		info.Err = ErrInvalidConnection
		return info
	}

	info.Addr = conn.RemoteAddr()
	info.PID = result
	return info
}
