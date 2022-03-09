//go:build windows
// +build windows

package healthcheck

import (
	"strconv"
	"testing"

	"github.com/spiffe/spire/test/spiretest"
	"google.golang.org/grpc"
)

var (
	socketAddrUsage = `
  -tcpSocketPort int
    	TCP port number of the SPIRE Agent API socket (default 8082)`
	socketAddrArg         = "-tcpSocketPort"
	socketAddrUnavailable = "8083"
	unavailableErr        = "Failed to check health: rpc error: code = Unavailable desc = connection error: desc = \"transport: Error while dialing dial tcp 127.0.0.1:8083: connectex: No connection could be made because the target machine actively refused it.\"\nAgent is unhealthy: unable to determine health\n"
)

func startGRPCSocketServer(t *testing.T, registerFn func(srv *grpc.Server)) string {
	return strconv.Itoa(spiretest.StartGRPCSocketServerOnFreeTCPSocket(t, registerFn).Port)
}
