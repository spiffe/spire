//go:build windows
// +build windows

package endpoints

import (
	"net"
	"testing"
)

func getTestAddr(t *testing.T) net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}
}
