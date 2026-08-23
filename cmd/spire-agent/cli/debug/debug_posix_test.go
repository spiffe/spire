//go:build !windows

package debug_test

var (
	usage = `Usage of debug getinfo:
  -output value
    	Desired output format (pretty, json); default: pretty.
  -socketPath string
    	Path to the SPIRE Agent admin API socket (default "/tmp/spire-agent/private/admin.sock")
`
	addrArg               = "-socketPath"
	socketAddrUnavailable = "/tmp/doesnotexist.sock"
)
