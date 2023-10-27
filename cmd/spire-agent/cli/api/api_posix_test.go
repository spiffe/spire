//go:build !windows

package api

const (
	fetchJWTUsage = `Usage of fetch jwt:
  -audience value
    	comma separated list of audience values
  -format value
    	deprecated; use -output
  -output value
    	Desired output format (pretty, json); default: pretty.
  -socketPath string
    	Path to the SPIRE Agent API Unix domain socket (default "/tmp/spire-agent/public/api.sock")
  -spiffeID string
    	SPIFFE ID subject (optional)
  -timeout value
    	Time to wait for a response (default 5s)
`
	fetchX509Usage = `Usage of fetch x509:
  -output value
    	Desired output format (pretty, json); default: pretty.
  -silent
    	Suppress stdout
  -socketPath string
    	Path to the SPIRE Agent API Unix domain socket (default "/tmp/spire-agent/public/api.sock")
  -timeout value
    	Time to wait for a response (default 5s)
  -write string
    	Write SVID data to the specified path (optional; only available for pretty output format)
`
	validateJWTUsage = `Usage of validate jwt:
  -audience string
    	expected audience value
  -output value
    	Desired output format (pretty, json); default: pretty.
  -socketPath string
    	Path to the SPIRE Agent API Unix domain socket (default "/tmp/spire-agent/public/api.sock")
  -svid string
    	JWT SVID
  -timeout value
    	Time to wait for a response (default 5s)
`
)
