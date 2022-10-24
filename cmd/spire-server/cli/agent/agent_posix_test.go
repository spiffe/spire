//go:build !windows
// +build !windows

package agent_test

var (
	listUsage = `Usage of agent list:
  -format value
    	Desired output format (pretty, json)
  -matchSelectorsOn string
    	The match mode used when filtering by selectors. Options: exact, any, superset and subset (default "superset")
  -selector value
    	A colon-delimited type:value selector. Can be used more than once
  -socketPath string
    	Path to the SPIRE Server API socket (default "/tmp/spire-server/private/api.sock")
`
	banUsage = `Usage of agent ban:
  -format value
    	Desired output format (pretty, json)
  -socketPath string
    	Path to the SPIRE Server API socket (default "/tmp/spire-server/private/api.sock")
  -spiffeID string
    	The SPIFFE ID of the agent to ban (agent identity)
`
	evictUsage = `Usage of agent evict:
  -format value
    	Desired output format (pretty, json)
  -socketPath string
    	Path to the SPIRE Server API socket (default "/tmp/spire-server/private/api.sock")
  -spiffeID string
    	The SPIFFE ID of the agent to evict (agent identity)
`
	countUsage = `Usage of agent count:
  -format value
    	Desired output format (pretty, json)
  -socketPath string
    	Path to the SPIRE Server API socket (default "/tmp/spire-server/private/api.sock")
`
	showUsage = `Usage of agent show:
  -format value
    	Desired output format (pretty, json)
  -socketPath string
    	Path to the SPIRE Server API socket (default "/tmp/spire-server/private/api.sock")
  -spiffeID string
    	The SPIFFE ID of the agent to show (agent identity)
`
)
