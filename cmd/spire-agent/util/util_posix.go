//go:build !windows

package util

import (
	"context"
	"flag"
	"net"
	"strings"

	"github.com/spiffe/spire/cmd/spire-agent/cli/common"
)

type adapterOS struct {
	adminSocketPath string
}

func (a *Adapter) addOSFlags(flags *flag.FlagSet) {
	flags.StringVar(&a.adminSocketPath, "socketPath", common.DefaultAdminSocketPath, "Path to the SPIRE Agent Admin API socket")
}

func (a *Adapter) getGRPCAddr() string {
	if a.adminSocketPath == "" {
		a.adminSocketPath = common.DefaultAdminSocketPath
	}

	return "unix:" + a.adminSocketPath
}

func dialer(ctx context.Context, addr string) (net.Conn, error) {
	socketPathAddr := strings.TrimPrefix(addr, "unix:")
	return (&net.Dialer{}).DialContext(ctx, "unix", socketPathAddr)
}
