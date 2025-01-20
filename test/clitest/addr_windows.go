//go:build windows

package clitest

import (
	"net"

	"github.com/spiffe/spire/pkg/common/namedpipe"
)

func GetAddr(addr net.Addr) string {
	return namedpipe.GetPipeName(addr.String())
}
