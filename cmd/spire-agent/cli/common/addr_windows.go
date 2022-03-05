//go:build windows
// +build windows

package common

import (
	"net"
)

func GetAddr(tcpSocketPort int) (*net.TCPAddr, error) {
	return &net.TCPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: tcpSocketPort,
	}, nil
}
