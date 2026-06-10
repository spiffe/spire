//go:build !windows

package logger_test

var (
	resetUsage = `Usage of logger reset:
  -output value
    	Desired output format (pretty, json); default: pretty.
  -socketPath string
    	Path to the SPIRE Agent Admin API socket (default "/tmp/spire-agent/private/admin.sock")
`
)
