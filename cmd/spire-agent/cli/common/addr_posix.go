//go:build !windows
// +build !windows

package common

import (
	"net"

	"github.com/spiffe/spire/pkg/common/util"
)

// GetAddr calls util.GetUnixAddrWithAbsPath to return
// the unix domain socket address with the designated
// socket path.
func GetAddr(socketPath string) (*net.UnixAddr, error) {
	return util.GetUnixAddrWithAbsPath(socketPath)
}
