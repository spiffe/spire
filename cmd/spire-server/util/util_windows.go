//go:build windows

package util

import (
	"context"
	"flag"
	"net"

	"github.com/Microsoft/go-winio"
	"github.com/spiffe/spire/pkg/common/namedpipe"
)

type adapterOS struct {
	namedPipeName string
}

func (a *Adapter) addOSFlags(flags *flag.FlagSet) {
	flags.StringVar(&a.namedPipeName, "namedPipeName", DefaultNamedPipeName, "Pipe name of the SPIRE Server API named pipe")
}

func dialer(ctx context.Context, addr string) (net.Conn, error) {
	return winio.DialPipeContext(ctx, addr)
}

func (a *Adapter) getAddr() (net.Addr, error) {
	if a.adapterOS.namedPipeName == "" {
		a.adapterOS.namedPipeName = DefaultNamedPipeName
	}
	return namedpipe.AddrFromName(a.namedPipeName), nil
}
