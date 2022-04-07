//go:build windows
// +build windows

package common

import (
	"flag"
	"net"

	"github.com/spiffe/spire/pkg/common/util"
)

type ConfigOS struct {
	namedPipePath string
}

func (c *ConfigOS) AddOSFlags(flags *flag.FlagSet) {
	flags.StringVar(&c.namedPipePath, "namedPipePath", DefaultNamedPipePath, "Path to the SPIRE Agent API Named Pipe socket")
}

func (c *ConfigOS) GetAddr() (net.Addr, error) {
	return util.GetNamedPipeAddr(c.namedPipePath)
}
