//go:build windows

package upstreamauthority_test

var (
	taintUsage = `Usage of upstreamauthority taint:
  -namedPipeName string
    	Pipe name of the SPIRE Server API named pipe (default "\\spire-server\\private\\api")
  -output value
    	Desired output format (pretty, json); default: pretty.
  -subjectKeyID string
    	The X.509 Subject Key Identifier (or SKID) of the authority's CA certificate of the upstream X.509 authority to taint
`
)
