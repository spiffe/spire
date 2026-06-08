//go:build !windows

package debug

import (
	"flag"
	"net"

	"github.com/spiffe/spire/cmd/spire-agent/cli/common"
	"github.com/spiffe/spire/pkg/common/util"
)

type getInfoCommandOS struct {
	socketPath string
}

func (c *getInfoCommandOS) addOSFlags(flags *flag.FlagSet) {
	flags.StringVar(&c.socketPath, "socketPath", common.DefaultAdminSocketPath, "Path to the SPIRE Agent admin API Unix domain socket")
}

func (c *getInfoCommandOS) getAddr() (net.Addr, error) {
	return util.GetUnixAddrWithAbsPath(c.socketPath)
}
