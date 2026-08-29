//go:build !windows

package x509_test

var (
	x509ActivateUsage = `Usage of localauthority x509 activate:
  -authorityID string
    	The authority ID of the X.509 authority to activate
  -instance string
    	Instance name to substitute into socket templates (env SPIRE_SERVER_PRIVATE_SOCKET_TEMPLATE).
  -output value
    	Desired output format (pretty, json); default: pretty.
  -socketPath string
    	Path to the SPIRE Server API socket (default "/tmp/spire-server/private/api.sock")
`
)
