//go:build !windows

package healthcheck

var (
	healthcheckUsage = `Usage of healthcheck:
  -s	Perform a less stringent health check
  -shallow
    	Perform a less stringent health check
  -socketPath string
    	Path to the SPIRE Server API socket (default "/tmp/spire-server/private/api.sock")
  -v	Print verbose information
  -verbose
    	Print verbose information
`
)
