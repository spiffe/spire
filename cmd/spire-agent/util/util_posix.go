//go:build !windows

package util

import (
	"context"
	"flag"
	"net"
	"strings"

	"github.com/spiffe/spire/cmd/spire-agent/cli/common"
)

const DefaultAdminSocketPath = common.DefaultAdminSocketPath

type adapterOS struct {
	socketPath string
}

func (a *Adapter) addOSFlags(flags *flag.FlagSet) {
	flags.StringVar(&a.socketPath, "socketPath", DefaultAdminSocketPath, "Path to the SPIRE Agent admin API socket")
}

func (a *Adapter) getGRPCAddr() string {
	if a.socketPath == "" {
		a.socketPath = DefaultAdminSocketPath
	}

	return "unix:" + a.socketPath
}

func dialer(ctx context.Context, addr string) (net.Conn, error) {
	socketPathAddr := strings.TrimPrefix(addr, "unix:")
	return (&net.Dialer{}).DialContext(ctx, "unix", socketPathAddr)
}
