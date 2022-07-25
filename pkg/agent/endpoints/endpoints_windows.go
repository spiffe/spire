//go:build windows
// +build windows

package endpoints

import (
	"fmt"
	"net"

	"github.com/Microsoft/go-winio"
	"github.com/spiffe/spire/pkg/common/peertracker"
	"github.com/spiffe/spire/pkg/common/sddl"
)

func (e *Endpoints) createPipeListener() (net.Listener, error) {
	pipeListener := &peertracker.ListenerFactory{
		Log: e.log,
	}
	l, err := pipeListener.ListenPipe(e.addr.String(), &winio.PipeConfig{SecurityDescriptor: sddl.PublicListener})
	if err != nil {
		return nil, fmt.Errorf("create named pipe listener: %w", err)
	}
	return l, nil
}

func (e *Endpoints) createListener() (net.Listener, error) {
	switch e.addr.Network() {
	case "unix":
		return nil, peertracker.ErrUnsupportedPlatform
	case "pipe":
		return e.createPipeListener()
	default:
		return nil, net.UnknownNetworkError(e.addr.Network())
	}
}
