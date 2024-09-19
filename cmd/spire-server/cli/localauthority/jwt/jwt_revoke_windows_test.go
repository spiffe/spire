//go:build windows

package jwt_test

var (
	jwtRevokeUsage = `Usage of localauthority jwt revoke:
  -authorityID string
    	The authority ID of the JWT authority to revoke
  -namedPipeName string
    	Pipe name of the SPIRE Server API named pipe (default "\\spire-server\\private\\api")
  -output value
    	Desired output format (pretty, json); default: pretty.
`
)
