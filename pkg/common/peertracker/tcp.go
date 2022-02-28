package peertracker

import (
	"net"
)

func CallerFromTCPConn(conn net.Conn) (CallerInfo, error) {
	return getCallerInfoFromTCPConn(conn)
}
