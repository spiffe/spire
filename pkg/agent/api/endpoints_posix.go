//go:build !windows
// +build !windows

package api

import (
	"fmt"
	"net"
	"os"
)

func (e *Endpoints) createUDSListener() (net.Listener, error) {
	// Remove uds if already exists
	os.Remove(e.c.BindAddr.String())

	l, err := e.unixListener.ListenUnix(e.c.BindAddr.Network(), e.c.BindAddr)
	if err != nil {
		return nil, fmt.Errorf("create UDS listener: %w", err)
	}
	if err := os.Chmod(e.c.BindAddr.String(), 0770); err != nil {
		return nil, fmt.Errorf("unable to change UDS permissions: %w", err)
	}
	return l, nil
}

func (e *Endpoints) createListener() (net.Listener, error) {
	return e.createUDSListener()
}
