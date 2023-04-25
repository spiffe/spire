//go:build !windows
// +build !windows

package agent_test

var (
	purgeUsage = `Usage of agent purge:
  -dryRun
    	Indicates that the command will not perform any action, but will print the agents that would be purged.
  -expiredFor duration
    	Amount of time that has passed since the agent's SVID has expired. It is used to determine which agents to purge. (default 720h0m0s)
  -output value
    	Desired output format (pretty, json); default: pretty.
  -socketPath string
    	Path to the SPIRE Server API socket (default "/tmp/spire-server/private/api.sock")
`
	listUsage = `Usage of agent list:
  -matchSelectorsOn string
    	The match mode used when filtering by selectors. Options: exact, any, superset and subset (default "superset")
  -output value
    	Desired output format (pretty, json); default: pretty.
  -selector value
    	A colon-delimited type:value selector. Can be used more than once
  -socketPath string
    	Path to the SPIRE Server API socket (default "/tmp/spire-server/private/api.sock")
`
	banUsage = `Usage of agent ban:
  -output value
    	Desired output format (pretty, json); default: pretty.
  -socketPath string
    	Path to the SPIRE Server API socket (default "/tmp/spire-server/private/api.sock")
  -spiffeID string
    	The SPIFFE ID of the agent to ban (agent identity)
`
	evictUsage = `Usage of agent evict:
  -output value
    	Desired output format (pretty, json); default: pretty.
  -socketPath string
    	Path to the SPIRE Server API socket (default "/tmp/spire-server/private/api.sock")
  -spiffeID string
    	The SPIFFE ID of the agent to evict (agent identity)
`
	countUsage = `Usage of agent count:
  -output value
    	Desired output format (pretty, json); default: pretty.
  -socketPath string
    	Path to the SPIRE Server API socket (default "/tmp/spire-server/private/api.sock")
`
	showUsage = `Usage of agent show:
  -output value
    	Desired output format (pretty, json); default: pretty.
  -socketPath string
    	Path to the SPIRE Server API socket (default "/tmp/spire-server/private/api.sock")
  -spiffeID string
    	The SPIFFE ID of the agent to show (agent identity)
`
)
