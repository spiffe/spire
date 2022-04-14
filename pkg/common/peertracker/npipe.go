package peertracker

import (
	"net"
)

func CallerFromPipeConn(conn net.Conn) (CallerInfo, error) {
	return getCallerInfoFromNamedPipeConn(conn)
}
