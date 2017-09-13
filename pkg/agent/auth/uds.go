package auth

import (
	"net"
	"syscall"

	"golang.org/x/net/context"

	"google.golang.org/grpc/credentials"
)

// TODO: Figure out portability - this only works on linux(?)
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

	ucred, err := syscall.GetsockoptUcred(int(file.Fd()), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	if err != nil {
		info.Err = err
		return info
	}

	info.Addr = uconn.RemoteAddr()
	info.PID = int(ucred.Pid)
	return info
}
