//go:build windows

package healthcheck

var (
	healthcheckUsage = `Usage of healthcheck:
  -instance string
    	Instance name to substitute into socket templates (env SPIRE_SERVER_PRIVATE_SOCKET_TEMPLATE).
  -namedPipeName string
    	Pipe name of the SPIRE Server API named pipe (default "\\spire-server\\private\\api")
  -shallow
    	Perform a less stringent health check
  -verbose
    	Print verbose information
`
)
