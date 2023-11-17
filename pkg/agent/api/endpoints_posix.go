//go:build !windows

package api

import (
	"fmt"
	"net"
	"os"

	"github.com/spiffe/spire/pkg/common/util"
)

func (e *Endpoints) createListener() (net.Listener, error) {
	// Remove uds if already exists
	os.Remove(e.c.BindAddr.String())

	l, err := e.listener.ListenUnix(e.c.BindAddr.Network(), util.GetUnixAddr(e.c.BindAddr.String()))
	if err != nil {
		return nil, fmt.Errorf("error creating UDS listener: %w", err)
	}
	if err := os.Chmod(e.c.BindAddr.String(), 0770); err != nil {
		return nil, fmt.Errorf("unable to change UDS permissions: %w", err)
	}
	return l, nil
}
