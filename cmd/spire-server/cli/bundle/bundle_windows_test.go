//go:build windows

package bundle

var (
	setUsage = `Usage of bundle set:
  -f string
    	The format of the bundle data. Either "pem" or "spiffe". (default "pem")
  -format string
    	The format of the bundle data. Either "pem" or "spiffe". (default "pem")
  -i string
    	SPIFFE ID of the trust domain
  -id string
    	SPIFFE ID of the trust domain
  -namedPipeName string
    	Pipe name of the SPIRE Server API named pipe (default "\\spire-server\\private\\api")
  -output value
    	Desired output format (pretty, json); default: pretty.
  -p string
    	Path to the bundle data
  -path string
    	Path to the bundle data
`
	showUsage = `Usage of bundle show:
  -f string
    	The format to show the bundle (only pretty output format supports this flag). Either "pem" or "spiffe". (default "pem")
  -format string
    	The format to show the bundle (only pretty output format supports this flag). Either "pem" or "spiffe". (default "pem")
  -namedPipeName string
    	Pipe name of the SPIRE Server API named pipe (default "\\spire-server\\private\\api")
  -output value
    	Desired output format (pretty, json); default: pretty.
`
	countUsage = `Usage of bundle count:
  -namedPipeName string
    	Pipe name of the SPIRE Server API named pipe (default "\\spire-server\\private\\api")
  -output value
    	Desired output format (pretty, json); default: pretty.
`
	listUsage = `Usage of bundle list:
  -f string
    	The format to list federated bundles (only pretty output format supports this flag). Either "pem" or "spiffe". (default "pem")
  -format string
    	The format to list federated bundles (only pretty output format supports this flag). Either "pem" or "spiffe". (default "pem")
  -i string
    	SPIFFE ID of the trust domain
  -id string
    	SPIFFE ID of the trust domain
  -namedPipeName string
    	Pipe name of the SPIRE Server API named pipe (default "\\spire-server\\private\\api")
  -output value
    	Desired output format (pretty, json); default: pretty.
`
	deleteUsage = `Usage of bundle delete:
  -i string
    	SPIFFE ID of the trust domain
  -id string
    	SPIFFE ID of the trust domain
  -mode string
    	Deletion mode: one of restrict, delete, or dissociate (default "restrict")
  -namedPipeName string
    	Pipe name of the SPIRE Server API named pipe (default "\\spire-server\\private\\api")
  -output value
    	Desired output format (pretty, json); default: pretty.
`
)
