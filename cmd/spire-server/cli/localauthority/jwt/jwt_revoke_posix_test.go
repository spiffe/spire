//go:build !windows

package jwt_test

var (
	jwtRevokeUsage = `Usage of localauthority jwt revoke:
  -authorityID string
    	The authority ID of the JWT authority to revoke
  -i string
    	Instance name to substitute into socket templates (env SPIRE_SERVER_PRIVATE_SOCKET_TEMPLATE). If omitted and the env var is set, defaults to 'main'.
  -output value
    	Desired output format (pretty, json); default: pretty.
  -socketPath string
    	Path to the SPIRE Server API socket (default "/tmp/spire-server/private/api.sock")
`
)
