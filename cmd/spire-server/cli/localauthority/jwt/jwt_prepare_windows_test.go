//go:build windows

package jwt_test

var (
	jwtPrepareUsage = `Usage of localauthority jwt prepare:
  -instance string
    	Instance name to substitute into socket templates (env SPIRE_SERVER_PRIVATE_SOCKET_TEMPLATE).
  -namedPipeName string
    	Pipe name of the SPIRE Server API named pipe (default "\\spire-server\\private\\api")
  -output value
    	Desired output format (pretty, json); default: pretty.
`
)