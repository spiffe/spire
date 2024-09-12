//go:build !windows

package x509_test

var (
	x509PrepareUsage = `Usage of localauthority x509 prepare:
  -output value
    	Desired output format (pretty, json); default: pretty.
  -socketPath string
    	Path to the SPIRE Server API socket (default "/tmp/spire-server/private/api.sock")
`
)
