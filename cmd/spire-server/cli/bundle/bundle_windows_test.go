//go:build windows
// +build windows

package bundle

var (
	setUsage = `Usage of bundle set:
  -format string
    	The format of the bundle data. Either "pem" or "spiffe". (default "pem")
  -id string
    	SPIFFE ID of the trust domain
  -namedPipeName string
    	Pipe name of the SPIRE Server API named pipe (default "\\spire-server\\private\\api")
  -path string
    	Path to the bundle data
`
)
