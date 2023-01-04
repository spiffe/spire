//go:build !windows
// +build !windows

package entry

const (
	createUsage = `Usage of entry create:
  -admin
    	If set, the SPIFFE ID in this entry will be granted access to the SPIRE Server's management APIs
  -data string
    	Path to a file containing registration JSON (optional). If set to '-', read the JSON from stdin.
  -dns value
    	A DNS name that will be included in SVIDs issued based on this entry, where appropriate. Can be used more than once
  -downstream
    	A boolean value that, when set, indicates that the entry describes a downstream SPIRE server
  -entryExpiry int
    	An expiry, from epoch in seconds, for the resulting registration entry to be pruned
  -federatesWith value
    	SPIFFE ID of a trust domain to federate with. Can be used more than once
  -jwtSVIDTTL int
    	The lifetime, in seconds, for JWT-SVIDs issued based on this registration entry. Overrides ttl flag
  -node
    	If set, this entry will be applied to matching nodes rather than workloads
  -output value
    	Desired output format (pretty, json); default: pretty.
  -parentID string
    	The SPIFFE ID of this record's parent
  -selector value
    	A colon-delimited type:value selector. Can be used more than once
  -socketPath string
    	Path to the SPIRE Server API socket (default "/tmp/spire-server/private/api.sock")
  -spiffeID string
    	The SPIFFE ID that this record represents
  -storeSVID
    	A boolean value that, when set, indicates that the resulting issued SVID from this entry must be stored through an SVIDStore plugin
  -ttl int
    	The lifetime, in seconds, for SVIDs issued based on this registration entry. This flag is deprecated in favor of x509SVIDTTL and jwtSVIDTTL and will be removed in a future version
  -x509SVIDTTL int
    	The lifetime, in seconds, for x509-SVIDs issued based on this registration entry. Overrides ttl flag
`
	showUsage = `Usage of entry show:
  -downstream
    	A boolean value that, when set, indicates that the entry describes a downstream SPIRE server
  -entryID string
    	The Entry ID of the records to show
  -federatesWith value
    	SPIFFE ID of a trust domain an entry is federate with. Can be used more than once
  -matchFederatesWithOn string
    	The match mode used when filtering by federates with. Options: exact, any, superset and subset (default "superset")
  -matchSelectorsOn string
    	The match mode used when filtering by selectors. Options: exact, any, superset and subset (default "superset")
  -output value
    	Desired output format (pretty, json); default: pretty.
  -parentID string
    	The Parent ID of the records to show
  -selector value
    	A colon-delimited type:value selector. Can be used more than once
  -socketPath string
    	Path to the SPIRE Server API socket (default "/tmp/spire-server/private/api.sock")
  -spiffeID string
    	The SPIFFE ID of the records to show
`
	updateUsage = `Usage of entry update:
  -admin
    	If set, the SPIFFE ID in this entry will be granted access to the SPIRE Server's management APIs
  -data string
    	Path to a file containing registration JSON (optional). If set to '-', read the JSON from stdin.
  -dns value
    	A DNS name that will be included in SVIDs issued based on this entry, where appropriate. Can be used more than once
  -downstream
    	A boolean value that, when set, indicates that the entry describes a downstream SPIRE server
  -entryExpiry int
    	An expiry, from epoch in seconds, for the resulting registration entry to be pruned
  -entryID string
    	The Registration Entry ID of the record to update
  -federatesWith value
    	SPIFFE ID of a trust domain to federate with. Can be used more than once
  -jwtSVIDTTL int
    	The lifetime, in seconds, for JWT-SVIDs issued based on this registration entry. Overrides ttl flag
  -output value
    	Desired output format (pretty, json); default: pretty.
  -parentID string
    	The SPIFFE ID of this record's parent
  -selector value
    	A colon-delimited type:value selector. Can be used more than once
  -socketPath string
    	Path to the SPIRE Server API socket (default "/tmp/spire-server/private/api.sock")
  -spiffeID string
    	The SPIFFE ID that this record represents
  -storeSVID
    	A boolean value that, when set, indicates that the resulting issued SVID from this entry must be stored through an SVIDStore plugin
  -ttl int
    	The lifetime, in seconds, for SVIDs issued based on this registration entry. This flag is deprecated in favor of x509SVIDTTL and jwtSVIDTTL and will be removed in a future version
  -x509SVIDTTL int
    	The lifetime, in seconds, for x509-SVIDs issued based on this registration entry. Overrides ttl flag
`
	deleteUsage = `Usage of entry delete:
  -entryID string
    	The Registration Entry ID of the record to delete
  -output value
    	Desired output format (pretty, json); default: pretty.
  -socketPath string
    	Path to the SPIRE Server API socket (default "/tmp/spire-server/private/api.sock")
`
	countUsage = `Usage of entry count:
  -output value
    	Desired output format (pretty, json); default: pretty.
  -socketPath string
    	Path to the SPIRE Server API socket (default "/tmp/spire-server/private/api.sock")
`
)
