//go:build !windows

package healthcheck

var (
	healthcheckUsage = `Usage of healthcheck:
  -instance string
    	Instance name to substitute into socket templates (env SPIRE_SERVER_PRIVATE_SOCKET_TEMPLATE). If omitted and the env var is set, defaults to 'main'.
  -shallow
    	Perform a less stringent health check
  -socketPath string
    	Path to the SPIRE Server API socket (default "/tmp/spire-server/private/api.sock")
  -verbose
    	Print verbose information
`
)
