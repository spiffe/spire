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

const DefaultAdminNamedPipeName = common.DefaultAdminNamedPipeName

type adapterOS struct {
	namedPipeName string
}

func (a *Adapter) addOSFlags(flags *flag.FlagSet) {
	flags.StringVar(&a.namedPipeName, "namedPipeName", DefaultAdminNamedPipeName, "Pipe name of the SPIRE Agent admin API named pipe")
}

func dialer(ctx context.Context, addr string) (net.Conn, error) {
	npipeAddr := strings.TrimPrefix(addr, "passthrough:")
	return winio.DialPipeContext(ctx, npipeAddr)
}

func (a *Adapter) getGRPCAddr() string {
	if a.namedPipeName == "" {
		a.namedPipeName = DefaultAdminNamedPipeName
	}

	return "passthrough:" + namedpipe.AddrFromName(a.namedPipeName).String()
}
