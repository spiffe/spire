//go:build !windows
// +build !windows

package bundle

var (
	setUsage = `Usage of bundle set:
  -format string
    	The format of the bundle data. Either "pem" or "spiffe". (default "pem")
  -id string
    	SPIFFE ID of the trust domain
  -path string
    	Path to the bundle data
  -socketPath string
    	Path to the SPIRE Server API socket (default "/tmp/spire-server/private/api.sock")
`
)
