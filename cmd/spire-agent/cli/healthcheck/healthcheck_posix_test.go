//go:build !windows

package healthcheck

import (
	"testing"

	"github.com/spiffe/spire/test/spiretest"
	"google.golang.org/grpc"
)

var (
	usage = `Usage of health:
  -shallow
    	Perform a less stringent health check
  -socketPath string
    	Path to the SPIRE Agent API socket (default "/tmp/spire-agent/public/api.sock")
  -verbose
    	Print verbose information
`
	socketAddrArg         = "-socketPath"
	socketAddrUnavailable = "/tmp/doesnotexist.sock"
	unavailableErr        = "Failed to check health: rpc error: code = Unavailable desc = connection error: desc = \"transport: Error while dialing: dial unix /tmp/doesnotexist.sock: connect: no such file or directory\"\nAgent is unhealthy: unable to determine health\n"
)

func startGRPCSocketServer(t *testing.T, registerFn func(srv *grpc.Server)) string {
	return spiretest.StartGRPCServer(t, registerFn).String()
}
