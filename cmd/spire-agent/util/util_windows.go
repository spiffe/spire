//go:build windows

package util

import (
	"context"
	"flag"
	"net"
	"strings"

	"github.com/Microsoft/go-winio"
	"github.com/spiffe/spire/cmd/spire-agent/cli/common"
	"github.com/spiffe/spire/pkg/common/namedpipe"
)

type adapterOS struct {
	adminNamedPipeName string
}

func (a *Adapter) addOSFlags(flags *flag.FlagSet) {
	flags.StringVar(&a.adminNamedPipeName, "namedPipeName", common.DefaultAdminNamedPipeName, "Pipe name of the SPIRE Agent Admin API named pipe")
}

func dialer(ctx context.Context, addr string) (net.Conn, error) {
	npipeAddr := strings.TrimPrefix(addr, "passthrough:")
	return winio.DialPipeContext(ctx, npipeAddr)
}

func (a *Adapter) getGRPCAddr() string {
	if a.adminNamedPipeName == "" {
		a.adminNamedPipeName = common.DefaultAdminNamedPipeName
	}

	return "passthrough:" + namedpipe.AddrFromName(a.adminNamedPipeName).String()
}
