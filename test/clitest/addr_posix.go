//go:build !windows

package clitest

import (
	"net"
)

func GetAddr(addr net.Addr) string {
	return addr.String()
}
