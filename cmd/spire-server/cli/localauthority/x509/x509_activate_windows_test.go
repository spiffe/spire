//go:build windows

package x509_test

var (
	x509ActivateUsage = `Usage of localauthority x509 activate:
  -authorityID string
    	The authority ID of the X.509 authority to activate
  -namedPipeName string
    	Pipe name of the SPIRE Server API named pipe (default "\\spire-server\\private\\api")
  -output value
    	Desired output format (pretty, json); default: pretty.
`
)
