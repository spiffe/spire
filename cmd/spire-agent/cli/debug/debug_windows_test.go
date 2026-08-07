//go:build windows

package debug_test

var (
	usage = `Usage of debug getinfo:
  -namedPipeName string
    	Pipe name of the SPIRE Agent admin API named pipe (default "\\spire-agent\\private\\admin")
  -output value
    	Desired output format (pretty, json); default: pretty.
`
	addrArg               = "-namedPipeName"
	socketAddrUnavailable = "doesnotexist"
)
