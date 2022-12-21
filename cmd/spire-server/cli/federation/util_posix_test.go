//go:build !windows
// +build !windows

package federation

const (
	createUsage = `Usage of federation create:
  -bundleEndpointProfile string
    	Endpoint profile type (either "https_web" or "https_spiffe")
  -bundleEndpointURL string
    	URL of the SPIFFE bundle endpoint that provides the trust bundle (must use the HTTPS protocol)
  -data string
    	Path to a file containing federation relationships in JSON format (optional). If set to '-', read the JSON from stdin.
  -endpointSpiffeID string
    	SPIFFE ID of the SPIFFE bundle endpoint server. Only used for 'spiffe' profile.
  -output value
    	Desired output format (pretty, json); default: pretty.
  -socketPath string
    	Path to the SPIRE Server API socket (default "/tmp/spire-server/private/api.sock")
  -trustDomain string
    	Name of the trust domain to federate with (e.g., example.org)
  -trustDomainBundleFormat string
    	The format of the bundle data (optional). Either "pem" or "spiffe". (default "pem")
  -trustDomainBundlePath string
    	Path to the trust domain bundle data (optional).
`
	deleteUsage = `Usage of federation delete:
  -id string
    	SPIFFE ID of the trust domain
  -output value
    	Desired output format (pretty, json); default: pretty.
  -socketPath string
    	Path to the SPIRE Server API socket (default "/tmp/spire-server/private/api.sock")
`
	listUsage = `Usage of federation list:
  -output value
    	Desired output format (pretty, json); default: pretty.
  -socketPath string
    	Path to the SPIRE Server API socket (default "/tmp/spire-server/private/api.sock")
`
	refreshUsage = `Usage of federation refresh:
  -id string
    	SPIFFE ID of the trust domain
  -output value
    	Desired output format (pretty, json); default: pretty.
  -socketPath string
    	Path to the SPIRE Server API socket (default "/tmp/spire-server/private/api.sock")
`
	showUsage = `Usage of federation show:
  -output value
    	Desired output format (pretty, json); default: pretty.
  -socketPath string
    	Path to the SPIRE Server API socket (default "/tmp/spire-server/private/api.sock")
  -trustDomain string
    	The trust domain name of the federation relationship to show
`
	updateUsage = `Usage of federation update:
  -bundleEndpointProfile string
    	Endpoint profile type (either "https_web" or "https_spiffe")
  -bundleEndpointURL string
    	URL of the SPIFFE bundle endpoint that provides the trust bundle (must use the HTTPS protocol)
  -data string
    	Path to a file containing federation relationships in JSON format (optional). If set to '-', read the JSON from stdin.
  -endpointSpiffeID string
    	SPIFFE ID of the SPIFFE bundle endpoint server. Only used for 'spiffe' profile.
  -output value
    	Desired output format (pretty, json); default: pretty.
  -socketPath string
    	Path to the SPIRE Server API socket (default "/tmp/spire-server/private/api.sock")
  -trustDomain string
    	Name of the trust domain to federate with (e.g., example.org)
  -trustDomainBundleFormat string
    	The format of the bundle data (optional). Either "pem" or "spiffe". (default "pem")
  -trustDomainBundlePath string
    	Path to the trust domain bundle data (optional).
`
)
