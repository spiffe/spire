//go:build windows
// +build windows

package common

import (
	"net"
)

// GetAddr returns the localhost IPv4 TCP address with the
// designated port
func GetAddr(tcpSocketPort int) (*net.TCPAddr, error) {
	return &net.TCPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: tcpSocketPort,
	}, nil
}
