//go:build !windows

package healthcheck

var (
	healthcheckUsage = `Usage of healthcheck:
  -shallow
    	Perform a less stringent health check
  -socketPath string
    	Path to the SPIRE Server API socket (default "/tmp/spire-server/private/api.sock")
  -verbose
    	Print verbose information
`
)
