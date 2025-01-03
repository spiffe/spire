//go:build !windows

package clitest

var (
	AddrArg         = "-socketPath"
	AddrError       = "rpc error: code = Unavailable desc = connection error: desc = \"transport: Error while dialing: dial unix ///does-not-exist.sock: connect: no such file or directory\"\n"
	AddrOutputUsage = `
  -output value
    	Desired output format (pretty, json); default: pretty.
  -socketPath string
    	Path to the SPIRE Server API socket (default "/tmp/spire-server/private/api.sock")
`
	AddrValue = "/does-not-exist.sock"
)
