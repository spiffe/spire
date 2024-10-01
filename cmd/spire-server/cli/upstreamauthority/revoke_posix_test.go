//go:build !windows

package upstreamauthority_test

var (
	revokeUsage = `Usage of upstreamauthority revoke:
  -output value
    	Desired output format (pretty, json); default: pretty.
  -socketPath string
    	Path to the SPIRE Server API socket (default "/tmp/spire-server/private/api.sock")
  -subjectKeyID string
    	The X.509 Subject Key Identifier (or SKID) of the authority's CA certificate of the X.509 upstream authority to revoke
`
)
