//go:build !windows

package bundle

var (
	setUsage = `Usage of bundle set:
  -format string
    	The format of the bundle data. Either "pem" or "spiffe". (default "pem")
  -id string
    	SPIFFE ID of the trust domain
  -output value
    	Desired output format (pretty, json); default: pretty.
  -path string
    	Path to the bundle data
  -socketPath string
    	Path to the SPIRE Server API socket (default "/tmp/spire-server/private/api.sock")
`
	countUsage = `Usage of bundle count:
  -output value
    	Desired output format (pretty, json); default: pretty.
  -socketPath string
    	Path to the SPIRE Server API socket (default "/tmp/spire-server/private/api.sock")
`
	deleteUsage = `Usage of bundle delete:
  -id string
    	SPIFFE ID of the trust domain
  -mode string
    	Deletion mode: one of restrict, delete, or dissociate (default "restrict")
  -output value
    	Desired output format (pretty, json); default: pretty.
  -socketPath string
    	Path to the SPIRE Server API socket (default "/tmp/spire-server/private/api.sock")
`
	listUsage = `Usage of bundle list:
  -format string
    	The format to list federated bundles (only pretty output format supports this flag). Either "pem" or "spiffe". (default "pem")
  -id string
    	SPIFFE ID of the trust domain
  -output value
    	Desired output format (pretty, json); default: pretty.
  -socketPath string
    	Path to the SPIRE Server API socket (default "/tmp/spire-server/private/api.sock")
`
	showUsage = `Usage of bundle show:
  -format string
    	The format to show the bundle (only pretty output format supports this flag). Either "pem" or "spiffe". (default "pem")
  -output value
    	Desired output format (pretty, json); default: pretty.
  -socketPath string
    	Path to the SPIRE Server API socket (default "/tmp/spire-server/private/api.sock")
`
)
