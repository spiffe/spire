//go:build !windows

package jwt_test

var (
	jwtShowUsage = `Usage of localauthority jwt show:
  -output value
    	Desired output format (pretty, json); default: pretty.
  -socketPath string
    	Path to the SPIRE Server API socket (default "/tmp/spire-server/private/api.sock")
`
)
