//go:build !windows

package jwt_test

var (
	jwtActivateUsage = `Usage of localauthority jwt activate:
  -authorityID string
    	The authority ID of the JWT authority to activate
  -output value
    	Desired output format (pretty, json); default: pretty.
  -socketPath string
    	Path to the SPIRE Server API socket (default "/tmp/spire-server/private/api.sock")
`
)
