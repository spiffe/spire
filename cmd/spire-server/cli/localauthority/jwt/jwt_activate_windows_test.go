//go:build windows

package jwt_test

var (
	jwtActivateUsage = `Usage of localauthority jwt activate:
  -authorityID string
    	The authority ID of the JWT authority to activate
  -namedPipeName string
    	Pipe name of the SPIRE Server API named pipe (default "\\spire-server\\private\\api")
  -output value
    	Desired output format (pretty, json); default: pretty.
`
)
