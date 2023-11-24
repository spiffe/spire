//go:build windows

package api

const (
	fetchJWTUsage = `Usage of fetch jwt:
  -audience value
    	comma separated list of audience values
  -format value
    	deprecated; use -output
  -namedPipeName string
    	Pipe name of the SPIRE Agent API named pipe (default "\\spire-agent\\public\\api")
  -output value
    	Desired output format (pretty, json); default: pretty.
  -spiffeID string
    	SPIFFE ID subject (optional)
  -timeout value
    	Time to wait for a response (default 5s)
`
	fetchX509Usage = `Usage of fetch x509:
  -namedPipeName string
    	Pipe name of the SPIRE Agent API named pipe (default "\\spire-agent\\public\\api")
  -output value
    	Desired output format (pretty, json); default: pretty.
  -silent
    	Suppress stdout
  -timeout value
    	Time to wait for a response (default 5s)
  -write string
    	Write SVID data to the specified path (optional; only available for pretty output format)
`
	validateJWTUsage = `Usage of validate jwt:
  -audience string
    	expected audience value
  -namedPipeName string
    	Pipe name of the SPIRE Agent API named pipe (default "\\spire-agent\\public\\api")
  -output value
    	Desired output format (pretty, json); default: pretty.
  -svid string
    	JWT SVID
  -timeout value
    	Time to wait for a response (default 5s)
`
)
