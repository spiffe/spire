//go:build !windows

package clitest

var (
	AddrArg         = "-socketPath"
	AddrError       = "rpc error: code = Unavailable desc = connection error: desc = \"transport: Error while dialing: dial unix ///does-not-exist.sock: connect: no such file or directory\"\n"
	AddrOutputUsage = `
  -instance string
    	Instance name to substitute into socket templates (env SPIRE_SERVER_PRIVATE_SOCKET_TEMPLATE). If omitted and the env var is set, defaults to 'main'.
  -output value
    	Desired output format (pretty, json); default: pretty.
  -socketPath string
    	Path to the SPIRE Server API socket (default "/tmp/spire-server/private/api.sock")
`
	AddrOutputForCasesWhereOptionsStartWithS = `
  -output value
    	Desired output format (pretty, json); default: pretty.
`
	AddrSocketPathUsageForCasesWhereOptionsStartWithS = `
  -socketPath string
    	Path to the SPIRE Server API socket (default "/tmp/spire-server/private/api.sock")
`
	AddrValue = "/does-not-exist.sock"
)
