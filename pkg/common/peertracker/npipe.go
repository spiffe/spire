package peertracker

import (
	"net"
)

func CallerFromNamedPipeConn(conn net.Conn) (CallerInfo, error) {
	return getCallerInfoFromNamedPipeConn(conn)
}
