//go:build !windows

package entry

const (
	createUsage = `Usage of entry create:
  -a	If set, the SPIFFE ID in this entry will be granted access to the SPIRE Server's management APIs
  -admin
    	If set, the SPIFFE ID in this entry will be granted access to the SPIRE Server's management APIs
  -d string
    	Path to a file containing registration JSON (optional). If set to '-', read the JSON from stdin.
  -data string
    	Path to a file containing registration JSON (optional). If set to '-', read the JSON from stdin.
  -dns value
    	A DNS name that will be included in SVIDs issued based on this entry, where appropriate. Can be used more than once
  -downstream
    	A boolean value that, when set, indicates that the entry describes a downstream SPIRE server
  -e string
    	A custom ID for this registration entry (optional). If not set, a new entry ID will be generated
  -entryExpiry int
    	An expiry, from epoch in seconds, for the resulting registration entry to be pruned
  -entryID string
    	A custom ID for this registration entry (optional). If not set, a new entry ID will be generated
  -f value
    	SPIFFE ID of a trust domain to federate with. Can be used more than once
  -federatesWith value
    	SPIFFE ID of a trust domain to federate with. Can be used more than once
  -hint string
    	The entry hint, used to disambiguate entries with the same SPIFFE ID
  -jwtSVIDTTL int
    	The lifetime, in seconds, for JWT-SVIDs issued based on this registration entry.
  -l value
    	A colon-delimited type:value selector. Can be used more than once
  -node
    	If set, this entry will be applied to matching nodes rather than workloads
  -output value
    	Desired output format (pretty, json); default: pretty.
  -p string
    	The SPIFFE ID of this record's parent
  -parentID string
    	The SPIFFE ID of this record's parent
  -s string
    	The SPIFFE ID that this record represents
  -selector value
    	A colon-delimited type:value selector. Can be used more than once
  -socketPath string
    	Path to the SPIRE Server API socket (default "/tmp/spire-server/private/api.sock")
  -spiffeID string
    	The SPIFFE ID that this record represents
  -storeSVID
    	A boolean value that, when set, indicates that the resulting issued SVID from this entry must be stored through an SVIDStore plugin
  -x509SVIDTTL int
    	The lifetime, in seconds, for x509-SVIDs issued based on this registration entry.
`
	showUsage = `Usage of entry show:
  -downstream
    	A boolean value that, when set, indicates that the entry describes a downstream SPIRE server
  -e string
    	The Entry ID of the records to show
  -entryID string
    	The Entry ID of the records to show
  -f value
    	SPIFFE ID of a trust domain an entry is federate with. Can be used more than once
  -federatesWith value
    	SPIFFE ID of a trust domain an entry is federate with. Can be used more than once
  -hint string
    	The Hint of the records to show (optional)
  -l value
    	A colon-delimited type:value selector. Can be used more than once
  -matchFederatesWithOn string
    	The match mode used when filtering by federates with. Options: exact, any, superset and subset (default "superset")
  -matchSelectorsOn string
    	The match mode used when filtering by selectors. Options: exact, any, superset and subset (default "superset")
  -output value
    	Desired output format (pretty, json); default: pretty.
  -p string
    	The Parent ID of the records to show
  -parentID string
    	The Parent ID of the records to show
  -s string
    	The SPIFFE ID of the records to show
  -selector value
    	A colon-delimited type:value selector. Can be used more than once
  -socketPath string
    	Path to the SPIRE Server API socket (default "/tmp/spire-server/private/api.sock")
  -spiffeID string
    	The SPIFFE ID of the records to show
`
	updateUsage = `Usage of entry update:
  -a	If set, the SPIFFE ID in this entry will be granted access to the SPIRE Server's management APIs
  -admin
    	If set, the SPIFFE ID in this entry will be granted access to the SPIRE Server's management APIs
  -d string
    	Path to a file containing registration JSON (optional). If set to '-', read the JSON from stdin.
  -data string
    	Path to a file containing registration JSON (optional). If set to '-', read the JSON from stdin.
  -dns value
    	A DNS name that will be included in SVIDs issued based on this entry, where appropriate. Can be used more than once
  -downstream
    	A boolean value that, when set, indicates that the entry describes a downstream SPIRE server
  -e string
    	The Registration Entry ID of the record to update
  -entryExpiry int
    	An expiry, from epoch in seconds, for the resulting registration entry to be pruned
  -entryID string
    	The Registration Entry ID of the record to update
  -f value
    	SPIFFE ID of a trust domain to federate with. Can be used more than once
  -federatesWith value
    	SPIFFE ID of a trust domain to federate with. Can be used more than once
  -hint string
    	The entry hint, used to disambiguate entries with the same SPIFFE ID
  -jwtSVIDTTL int
    	The lifetime, in seconds, for JWT-SVIDs issued based on this registration entry.
  -l value
    	A colon-delimited type:value selector. Can be used more than once
  -output value
    	Desired output format (pretty, json); default: pretty.
  -p string
    	The SPIFFE ID of this record's parent
  -parentID string
    	The SPIFFE ID of this record's parent
  -s string
    	The SPIFFE ID that this record represents
  -selector value
    	A colon-delimited type:value selector. Can be used more than once
  -socketPath string
    	Path to the SPIRE Server API socket (default "/tmp/spire-server/private/api.sock")
  -spiffeID string
    	The SPIFFE ID that this record represents
  -storeSVID
    	A boolean value that, when set, indicates that the resulting issued SVID from this entry must be stored through an SVIDStore plugin
  -x509SVIDTTL int
    	The lifetime, in seconds, for x509-SVIDs issued based on this registration entry.
`
	deleteUsage = `Usage of entry delete:
  -e string
    	The Registration Entry ID of the record to delete.
  -entryID string
    	The Registration Entry ID of the record to delete.
  -f string
    	Path to a file containing a JSON structure for batch deletion (optional). If set to '-', read from stdin.
  -file string
    	Path to a file containing a JSON structure for batch deletion (optional). If set to '-', read from stdin.
  -output value
    	Desired output format (pretty, json); default: pretty.
  -socketPath string
    	Path to the SPIRE Server API socket (default "/tmp/spire-server/private/api.sock")
`
	countUsage = `Usage of entry count:
  -downstream
    	A boolean value that, when set, indicates that the entry describes a downstream SPIRE server
  -f value
    	SPIFFE ID of a trust domain an entry is federate with. Can be used more than once
  -federatesWith value
    	SPIFFE ID of a trust domain an entry is federate with. Can be used more than once
  -hint string
    	The Hint of the records to count (optional)
  -l value
    	A colon-delimited type:value selector. Can be used more than once
  -matchFederatesWithOn string
    	The match mode used when filtering by federates with. Options: exact, any, superset and subset (default "superset")
  -matchSelectorsOn string
    	The match mode used when filtering by selectors. Options: exact, any, superset and subset (default "superset")
  -output value
    	Desired output format (pretty, json); default: pretty.
  -p string
    	The Parent ID of the records to count
  -parentID string
    	The Parent ID of the records to count
  -s string
    	The SPIFFE ID of the records to count
  -selector value
    	A colon-delimited type:value selector. Can be used more than once
  -socketPath string
    	Path to the SPIRE Server API socket (default "/tmp/spire-server/private/api.sock")
  -spiffeID string
    	The SPIFFE ID of the records to count
`
)
