package peertracker

import (
	"net"
	"syscall"
)

func CallerFromUDSConn(conn net.Conn) (CallerInfo, error) {
	var info CallerInfo

	sysconn, ok := conn.(syscall.Conn)
	if !ok {
		return info, ErrInvalidConnection
	}

	rawconn, err := sysconn.SyscallConn()
	if err != nil {
		return info, err
	}

	ctrlErr := rawconn.Control(func(fd uintptr) {
		info, err = getCallerInfo(fd)
	})
	if ctrlErr != nil {
		return info, ctrlErr
	}
	if err != nil {
		return info, err
	}

	info.Addr = conn.RemoteAddr()
	return info, nil
}
