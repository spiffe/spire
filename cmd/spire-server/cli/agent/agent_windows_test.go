//go:build windows
// +build windows

package agent_test

var (
	listUsage = `Usage of agent list:
  -matchSelectorsOn string
    	The match mode used when filtering by selectors. Options: exact, any, superset and subset (default "superset")
  -namedPipeName string
    	Pipe name of the SPIRE Server API named pipe (default "\\spire-server\\private\\api")
  -selector value
    	A colon-delimited type:value selector. Can be used more than once
`
)
