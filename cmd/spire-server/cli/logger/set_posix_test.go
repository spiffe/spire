//go:build !windows

package logger_test

var (
	setUsage = `Usage of logger set:
  -instance string
    	Instance name to substitute into socket templates (env SPIRE_SERVER_PRIVATE_SOCKET_TEMPLATE).
  -level string
    	The new log level, one of (panic, fatal, error, warn, info, debug, trace)
  -output value
    	Desired output format (pretty, json); default: pretty.
  -socketPath string
    	Path to the SPIRE Server API socket (default "/tmp/spire-server/private/api.sock")
`
)
