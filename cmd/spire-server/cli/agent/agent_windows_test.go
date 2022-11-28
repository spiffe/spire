//go:build windows
// +build windows

package agent_test

var (
	listUsage = `Usage of agent list:
  -matchSelectorsOn string
    	The match mode used when filtering by selectors. Options: exact, any, superset and subset (default "superset")
  -namedPipeName string
    	Pipe name of the SPIRE Server API named pipe (default "\\spire-server\\private\\api")
  -output value
    	Desired output format (pretty, json)
  -selector value
    	A colon-delimited type:value selector. Can be used more than once
`
	banUsage = `Usage of agent ban:
  -namedPipeName string
    	Pipe name of the SPIRE Server API named pipe (default "\\spire-server\\private\\api")
  -output value
    	Desired output format (pretty, json)
  -spiffeID string
    	The SPIFFE ID of the agent to ban (agent identity)
`
	evictUsage = `Usage of agent evict:
  -namedPipeName string
    	Pipe name of the SPIRE Server API named pipe (default "\\spire-server\\private\\api")
  -output value
    	Desired output format (pretty, json)
  -spiffeID string
    	The SPIFFE ID of the agent to evict (agent identity)
`
	countUsage = `Usage of agent count:
  -namedPipeName string
    	Pipe name of the SPIRE Server API named pipe (default "\\spire-server\\private\\api")
  -output value
    	Desired output format (pretty, json)
`
	showUsage = `Usage of agent show:
  -namedPipeName string
    	Pipe name of the SPIRE Server API named pipe (default "\\spire-server\\private\\api")
  -output value
    	Desired output format (pretty, json)
  -spiffeID string
    	The SPIFFE ID of the agent to show (agent identity)
`
)
