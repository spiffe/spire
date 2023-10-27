//go:build windows

package healthcheck

var (
	healthcheckUsage = `Usage of healthcheck:
  -namedPipeName string
    	Pipe name of the SPIRE Server API named pipe (default "\\spire-server\\private\\api")
  -shallow
    	Perform a less stringent health check
  -verbose
    	Print verbose information
`
)
