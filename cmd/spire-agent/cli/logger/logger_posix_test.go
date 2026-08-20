//go:build !windows

package logger_test

const (
	addrArg     = "-socketPath"
	defaultPath = "/tmp/spire-agent/private/admin.sock"
)

var (
	getUsage = `Usage of logger get:
  -output value
    	Desired output format (pretty, json); default: pretty.
  -socketPath string
    	Path to the SPIRE Agent admin API socket (default "/tmp/spire-agent/private/admin.sock")
`
	setUsage = `Usage of logger set:
  -level string
    	The new log level, one of (panic, fatal, error, warn, info, debug, trace)
  -output value
    	Desired output format (pretty, json); default: pretty.
  -socketPath string
    	Path to the SPIRE Agent admin API socket (default "/tmp/spire-agent/private/admin.sock")
`
	resetUsage = `Usage of logger reset:
  -output value
    	Desired output format (pretty, json); default: pretty.
  -socketPath string
    	Path to the SPIRE Agent admin API socket (default "/tmp/spire-agent/private/admin.sock")
`
)
