package peertracker

import (
	"net"
)

func CallerFromUDSConn(conn net.Conn) (CallerInfo, error) {
	var info CallerInfo

	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return info, ErrInvalidConnection
	}

	rawconn, err := unixConn.SyscallConn()
	if err != nil {
		return info, err
	}

	ctrlErr := rawconn.Control(func(fd uintptr) {
		info, err = getCallerInfoFromFileDescriptor(fd)
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
