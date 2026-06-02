//go:build windows

package upstreamauthority_test

var (
	revokeUsage = `Usage of upstreamauthority revoke:
  -instance string
        Instance name to substitute into socket templates (env SPIRE_SERVER_PRIVATE_SOCKET_TEMPLATE).
  -namedPipeName string
    	Pipe name of the SPIRE Server API named pipe (default "\\spire-server\\private\\api")
  -output value
    	Desired output format (pretty, json); default: pretty.
  -subjectKeyID string
    	The X.509 Subject Key Identifier (or SKID) of the authority's CA certificate of the X.509 upstream authority to revoke
`
)
