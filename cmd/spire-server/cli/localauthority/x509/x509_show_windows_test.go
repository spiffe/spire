//go:build windows

package localauthority_test

var (
	x509ShowUsage = `Usage of localauthority x509 show:
  -namedPipeName string
    	Pipe name of the SPIRE Server API named pipe (default "\\spire-server\\private\\api")
  -output value
    	Desired output format (pretty, json); default: pretty.
`
)
