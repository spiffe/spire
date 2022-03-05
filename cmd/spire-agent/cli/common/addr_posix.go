//go:build !windows
// +build !windows

package common

import (
	"net"

	"github.com/spiffe/spire/pkg/common/util"
)

func GetAddr(socketPath string) (*net.UnixAddr, error) {
	return util.GetUnixAddrWithAbsPath(socketPath)
}
