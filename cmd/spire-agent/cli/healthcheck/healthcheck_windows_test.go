//go:build windows
// +build windows

package healthcheck

import (
	"testing"

	"github.com/spiffe/spire/pkg/common/namedpipe"
	"github.com/spiffe/spire/test/spiretest"
	"google.golang.org/grpc"
)

var (
	usage = `Usage of health:
  -namedPipeName string
    	Pipe name of the SPIRE Agent API named pipe (default "\\spire-agent\\public\\api")
  -shallow
    	Perform a less stringent health check
  -verbose
    	Print verbose information
`
	socketAddrArg         = "-namedPipeName"
	socketAddrUnavailable = "doesnotexist"
	unavailableErr        = "Failed to check health: rpc error: code = Unavailable desc = connection error: desc = \"transport: Error while dialing open \\\\\\\\.\\\\pipe\\\\doesnotexist: The system cannot find the file specified.\"\nAgent is unhealthy: unable to determine health\n"
)

func startGRPCSocketServer(t *testing.T, registerFn func(srv *grpc.Server)) string {
	return namedpipe.GetPipeName(spiretest.StartGRPCServer(t, registerFn).String())
}
