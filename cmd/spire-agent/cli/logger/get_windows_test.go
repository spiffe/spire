//go:build windows

package logger_test

var (
	getUsage = `Usage of logger get:
  -namedPipeName string
    	Pipe name of the SPIRE Agent Admin API named pipe (default "\\spire-agent\\private\\admin")
  -output value
    	Desired output format (pretty, json); default: pretty.
`
)
