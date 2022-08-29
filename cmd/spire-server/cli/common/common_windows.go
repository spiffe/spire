//go:build windows
// +build windows

package common

import (
	"net"

	"github.com/spiffe/spire/pkg/common/namedpipe"
)

var (
	AddrArg   = "-namedPipeName"
	AddrError = "Error: connection error: desc = \"transport: error while dialing: open \\\\\\\\.\\\\pipe\\\\does-not-exist: The system cannot find the file specified.\"\n"
	AddrUsage = `
  -namedPipeName string
    	Pipe name of the SPIRE Server API named pipe (default "\\spire-server\\private\\api")
`
	AddrValue = "\\does-not-exist"
)

func GetAddr(addr net.Addr) string {
	return namedpipe.GetPipeName(addr.String())
}
