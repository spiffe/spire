//go:build windows

package logger_test

var (
	setUsage = `Usage of logger set:
  -level string
    	The new log level, one of (panic, fatal, error, warn, info, debug, trace)
  -namedPipeName string
    	Pipe name of the SPIRE Agent Admin API named pipe (default "\\spire-agent\\private\\admin")
  -output value
    	Desired output format (pretty, json); default: pretty.
`
)
