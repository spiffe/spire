//go:build !windows
// +build !windows

package healthcheck

import (
	"context"
	"flag"
	"net"

	"github.com/spiffe/spire/cmd/spire-agent/cli/common"
	"github.com/spiffe/spire/pkg/common/util"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// healthCheckCommandOS has posix specific implementation
// that complements healthCheckCommand
type healthCheckCommandOS struct {
	socketPath string
}

func (c *healthCheckCommandOS) addOSFlags(flags *flag.FlagSet) {
	flags.StringVar(&c.socketPath, "socketPath", common.DefaultSocketPath, "Path to the SPIRE Agent API socket")
}

func (c *healthCheckCommandOS) getAddr() (net.Addr, error) {
	return util.GetUnixAddrWithAbsPath(c.socketPath)
}

func dial(target string) (*grpc.ClientConn, error) {
	return grpc.DialContext(context.Background(), target, grpc.WithTransportCredentials(insecure.NewCredentials()))
}
