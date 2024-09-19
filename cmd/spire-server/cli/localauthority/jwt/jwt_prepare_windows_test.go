//go:build windows

package jwt_test

var (
	jwtPrepareUsage = `Usage of localauthority jwt prepare:
  -namedPipeName string
    	Pipe name of the SPIRE Server API named pipe (default "\\spire-server\\private\\api")
  -output value
    	Desired output format (pretty, json); default: pretty.
`
)
