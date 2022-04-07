//go:build windows
// +build windows

package healthcheck

import (
	"context"
	"flag"
	"net"

	"github.com/Microsoft/go-winio"
	"github.com/spiffe/spire/cmd/spire-agent/cli/common"
	"github.com/spiffe/spire/pkg/common/util"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// healthCheckCommandOS has windows specific implementation
// that complements healthCheckCommand
type healthCheckCommandOS struct {
	namedPipePath string
}

func (c *healthCheckCommandOS) addOSFlags(flags *flag.FlagSet) {
	flags.StringVar(&c.namedPipePath, "namedPipePath", common.DefaultNamedPipePath, "Path of the SPIRE Agent API named pipe")
}

func (c *healthCheckCommandOS) getAddr() (net.Addr, error) {
	return util.GetNamedPipeAddr(c.namedPipePath)
}

func dial(target string) (*grpc.ClientConn, error) {
	return grpc.DialContext(context.Background(), target, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(winio.DialPipeContext))
}
