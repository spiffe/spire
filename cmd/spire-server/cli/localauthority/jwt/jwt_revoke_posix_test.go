//go:build !windows

package jwt_test

var (
	jwtRevokeUsage = `Usage of localauthority jwt revoke:
  -authorityID string
    	The authority ID of the JWT authority to revoke
  -output value
    	Desired output format (pretty, json); default: pretty.
  -socketPath string
    	Path to the SPIRE Server API socket (default "/tmp/spire-server/private/api.sock")
`
)
