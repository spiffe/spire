//go:build !windows

package localauthority_test

var (
	x509ShowUsage = `Usage of localauthority x509 show:
  -output value
    	Desired output format (pretty, json); default: pretty.
  -socketPath string
    	Path to the SPIRE Server API socket (default "/tmp/spire-server/private/api.sock")
`
)
