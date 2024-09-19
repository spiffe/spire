//go:build windows

package x509_test

var (
	x509TaintUsage = `Usage of localauthority x509 taint:
  -authorityID string
    	The authority ID of the X.509 authority to taint
  -namedPipeName string
    	Pipe name of the SPIRE Server API named pipe (default "\\spire-server\\private\\api")
  -output value
    	Desired output format (pretty, json); default: pretty.
`
)
