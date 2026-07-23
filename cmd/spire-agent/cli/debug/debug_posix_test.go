//go:build !windows

package debug

import (
	"testing"

	"github.com/spiffe/spire/test/spiretest"
	"google.golang.org/grpc"
)

var (
	usage = `Usage of debug getinfo:
  -output value
    	Desired output format (pretty, json); default: pretty.
  -socketPath string
    	Path to the SPIRE Agent admin API Unix domain socket (default "/tmp/spire-agent/private/admin.sock")
`
	socketAddrArg         = "-socketPath"
	socketAddrUnavailable = "/tmp/doesnotexist.sock"
)

func startGRPCSocketServer(t *testing.T, registerFn func(srv *grpc.Server)) string {
	return spiretest.StartGRPCServer(t, registerFn).String()
}
