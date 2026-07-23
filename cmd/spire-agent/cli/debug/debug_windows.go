//go:build windows

package debug

import (
	"flag"
	"net"

	"github.com/spiffe/spire/cmd/spire-agent/cli/common"
	"github.com/spiffe/spire/pkg/common/namedpipe"
)

type getInfoCommandOS struct {
	namedPipeName string
}

func (c *getInfoCommandOS) addOSFlags(flags *flag.FlagSet) {
	flags.StringVar(&c.namedPipeName, "namedPipeName", common.DefaultAdminNamedPipeName, "Pipe name of the SPIRE Agent admin API named pipe")
}

func (c *getInfoCommandOS) getAddr() (net.Addr, error) {
	return namedpipe.AddrFromName(c.namedPipeName), nil
}
