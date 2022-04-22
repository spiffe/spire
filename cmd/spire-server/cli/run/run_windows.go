//go:build windows
// +build windows

package run

import (
	"flag"
	"net"

	util_cmd "github.com/spiffe/spire/cmd/spire-server/util"
	"github.com/spiffe/spire/pkg/common/util"
)

func (c *serverConfig) addOSFlags(flags *flag.FlagSet) {
	flags.StringVar(&c.Experimental.NamedPipeName, "namedPipeName", "", "Pipe name of the SPIRE Server API named pipe")
}

func (c *serverConfig) getAddr() (net.Addr, error) {
	return util.GetNamedPipeAddr(c.Experimental.NamedPipeName), nil
}

func (c *serverConfig) setDefaultsIfNeeded() {
	if c.Experimental.NamedPipeName == "" {
		c.Experimental.NamedPipeName = util_cmd.DefaultNamedPipeName
	}
}
