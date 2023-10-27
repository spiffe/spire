//go:build !windows

package common

import "net"

var (
	AddrArg         = "-socketPath"
	AddrError       = "Error: connection error: desc = \"transport: error while dialing: dial unix /does-not-exist.sock: connect: no such file or directory\"\n"
	AddrOutputUsage = `
  -output value
    	Desired output format (pretty, json); default: pretty.
  -socketPath string
    	Path to the SPIRE Server API socket (default "/tmp/spire-server/private/api.sock")
`
	AddrValue = "/does-not-exist.sock"
)

func GetAddr(addr net.Addr) string {
	return addr.String()
}
