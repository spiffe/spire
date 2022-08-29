//go:build windows
// +build windows

package common

import (
	"flag"
	"net"

	"github.com/spiffe/spire/pkg/common/namedpipe"
)

type ConfigOS struct {
	namedPipeName string
}

func (c *ConfigOS) AddOSFlags(flags *flag.FlagSet) {
	flags.StringVar(&c.namedPipeName, "namedPipeName", DefaultNamedPipeName, "Pipe name of the SPIRE Agent API named pipe")
}

func (c *ConfigOS) GetAddr() (net.Addr, error) {
	return namedpipe.AddrFromName(c.namedPipeName), nil
}
