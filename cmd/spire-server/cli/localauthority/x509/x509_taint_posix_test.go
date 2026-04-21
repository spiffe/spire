//go:build !windows

package x509_test

var (
	x509TaintUsage = `Usage of localauthority x509 taint:
  -authorityID string
    	The authority ID of the X.509 authority to taint
  -instance string
    	Instance name to substitute into socket templates (env SPIRE_SERVER_PRIVATE_SOCKET_TEMPLATE). If omitted and the env var is set, defaults to 'main'.
  -output value
    	Desired output format (pretty, json); default: pretty.
  -socketPath string
    	Path to the SPIRE Server API socket (default "/tmp/spire-server/private/api.sock")
`
)
