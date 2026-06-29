//go:build windows

package logger_test

const (
	addrArg     = "-namedPipeName"
	defaultPath = "\\spire-agent\\private\\admin"
)

var (
	getUsage = `Usage of logger get:
  -namedPipeName string
    	Pipe name of the SPIRE Agent admin API named pipe (default "\\spire-agent\\private\\admin")
  -output value
    	Desired output format (pretty, json); default: pretty.
`
	setUsage = `Usage of logger set:
  -level string
    	The new log level, one of (panic, fatal, error, warn, info, debug, trace)
  -namedPipeName string
    	Pipe name of the SPIRE Agent admin API named pipe (default "\\spire-agent\\private\\admin")
  -output value
    	Desired output format (pretty, json); default: pretty.
`
	resetUsage = `Usage of logger reset:
  -namedPipeName string
    	Pipe name of the SPIRE Agent admin API named pipe (default "\\spire-agent\\private\\admin")
  -output value
    	Desired output format (pretty, json); default: pretty.
`
)
