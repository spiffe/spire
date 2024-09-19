//go:build !windows

package jwt_test

var (
	jwtPrepareUsage = `Usage of localauthority jwt prepare:
  -output value
    	Desired output format (pretty, json); default: pretty.
  -socketPath string
    	Path to the SPIRE Server API socket (default "/tmp/spire-server/private/api.sock")
`
)
