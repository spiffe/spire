//go:build windows

package upstreamauthority_test

var (
	revokeUsage = `Usage of upstreamauthority revoke:
  -output value
    	Desired output format (pretty, json); default: pretty.
  -namedPipeName string
    	Pipe name of the SPIRE Server API named pipe (default "\\spire-server\\private\\api")
  -subjectKeyID string
    	The X.509 Subject Key Identifier (or SKID) of the authority's CA certificate of the upstream X.509 authority to revoke
`
)
