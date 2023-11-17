//go:build windows

package namedpipe

import (
	"fmt"
	"net"
	"path/filepath"
	"strings"
)

type Addr struct {
	serverName string
	pipeName   string
}

func (p *Addr) PipeName() string {
	return p.pipeName
}

func (p *Addr) Network() string {
	return "pipe"
}

func (p *Addr) String() string {
	return fmt.Sprintf(`\\%s\%s`, p.serverName, filepath.Join("pipe", p.pipeName))
}

// AddrFromName returns a named pipe in the local
// computer with the specified pipe name
func AddrFromName(pipeName string) net.Addr {
	return &Addr{
		serverName: ".",
		pipeName:   pipeName,
	}
}

func GetPipeName(addr string) string {
	return strings.TrimPrefix(addr, `\\.\pipe`)
}
