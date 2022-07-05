//go:build windows
// +build windows

package api

import (
	"fmt"
	"net"

	"github.com/Microsoft/go-winio"
	"github.com/spiffe/spire/pkg/common/util"
)

func (e *Endpoints) createListener() (net.Listener, error) {
	l, err := e.listener.ListenPipe(e.c.BindAddr.String(), &winio.PipeConfig{SecurityDescriptor: util.SDDLPrivateListener})
	if err != nil {
		return nil, fmt.Errorf("error creating named pipe listener: %w", err)
	}
	return l, nil
}
