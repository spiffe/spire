//go:build windows

package common

import (
	"net"

	"github.com/spiffe/spire/pkg/common/namedpipe"
)

var (
	AddrArg         = "-namedPipeName"
	AddrError       = "Error: connection error: desc = \"transport: error while dialing: open \\\\\\\\.\\\\pipe\\\\does-not-exist: The system cannot find the file specified.\"\n"
	AddrOutputUsage = `
  -namedPipeName string
    	Pipe name of the SPIRE Server API named pipe (default "\\spire-server\\private\\api")
  -output value
    	Desired output format (pretty, json); default: pretty.
`
	AddrValue = "\\does-not-exist"
)

func GetAddr(addr net.Addr) string {
	return namedpipe.GetPipeName(addr.String())
}
