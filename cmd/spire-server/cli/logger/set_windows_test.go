//go:build windows

package logger_test

var (
	setUsage = `Usage of logger set:
  -instance string
    	Instance name to substitute into socket templates (env SPIRE_SERVER_PRIVATE_SOCKET_TEMPLATE).

  -level string
    	The new log level, one of (panic, fatal, error, warn, info, debug, trace)
  -namedPipeName string
    	Pipe name of the SPIRE Server API named pipe (default "\\spire-server\\private\\api")
  -output value
    	Desired output format (pretty, json); default: pretty.
`
)
