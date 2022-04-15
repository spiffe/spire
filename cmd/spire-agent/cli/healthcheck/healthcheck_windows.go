//go:build windows
// +build windows

package healthcheck

import (
	"flag"
	"net"

	"github.com/spiffe/spire/cmd/spire-agent/cli/common"
	"github.com/spiffe/spire/pkg/common/util"
)

// healthCheckCommandOS has windows specific implementation
// that complements healthCheckCommand
type healthCheckCommandOS struct {
	namedPipeName string
}

func (c *healthCheckCommandOS) addOSFlags(flags *flag.FlagSet) {
	flags.StringVar(&c.namedPipeName, "namedPipeName", common.DefaultNamedPipeName, "Pipe name of the SPIRE Agent API named pipe")
}

func (c *healthCheckCommandOS) getAddr() (net.Addr, error) {
	return util.GetNamedPipeAddr(c.namedPipeName), nil
}
