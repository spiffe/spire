package peertracker

import (
	"net"
)

var (
	localHost = net.IPv4(127, 0, 0, 1)
)

func CallerFromTCPConn(conn net.Conn) (CallerInfo, error) {
	return getCallerInfoFromTCPConn(conn)
}
