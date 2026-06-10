//go:build !windows

package logger_test

var (
	setUsage = `Usage of logger set:
  -level string
    	The new log level, one of (panic, fatal, error, warn, info, debug, trace)
  -output value
    	Desired output format (pretty, json); default: pretty.
  -socketPath string
    	Path to the SPIRE Agent Admin API socket (default "/tmp/spire-agent/private/admin.sock")
`
)
