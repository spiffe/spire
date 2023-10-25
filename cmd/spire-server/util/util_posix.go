//go:build !windows

package util

import (
	"context"
	"flag"
	"net"

	"github.com/spiffe/spire/pkg/common/util"
)

type adapterOS struct {
	socketPath string
}

func (a *Adapter) addOSFlags(flags *flag.FlagSet) {
	flags.StringVar(&a.socketPath, "socketPath", DefaultSocketPath, "Path to the SPIRE Server API socket")
}

func (a *Adapter) getAddr() (net.Addr, error) {
	if a.adapterOS.socketPath == "" {
		a.socketPath = DefaultSocketPath
	}
	return util.GetUnixAddrWithAbsPath(a.socketPath)
}

func dialer(ctx context.Context, addr string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, "unix", addr)
}
