//go:build windows

package logger_test

var (
	resetUsage = `Usage of logger reset:
  -namedPipeName string
    	Pipe name of the SPIRE Agent Admin API named pipe (default "\\spire-agent\\private\\admin")
  -output value
    	Desired output format (pretty, json); default: pretty.
`
)
