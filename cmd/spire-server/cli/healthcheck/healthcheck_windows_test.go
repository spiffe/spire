//go:build windows

package healthcheck

var (
	healthcheckUsage = `Usage of healthcheck:
  -namedPipeName string
    	Pipe name of the SPIRE Server API named pipe (default "\\spire-server\\private\\api")
  -s	Perform a less stringent health check
  -shallow
    	Perform a less stringent health check
  -v	Print verbose information
  -verbose
    	Print verbose information
`
)
