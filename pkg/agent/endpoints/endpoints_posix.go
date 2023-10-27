//go:build !windows

package endpoints

import (
	"fmt"
	"net"
	"os"

	"github.com/spiffe/spire/pkg/common/peertracker"
)

func (e *Endpoints) createUDSListener() (net.Listener, error) {
	// Remove uds if already exists
	os.Remove(e.addr.String())

	unixListener := &peertracker.ListenerFactory{
		Log: e.log,
	}

	unixAddr, ok := e.addr.(*net.UnixAddr)
	if !ok {
		return nil, fmt.Errorf("create UDS listener: address is type %T, not net.UnixAddr", e.addr)
	}
	l, err := unixListener.ListenUnix(e.addr.Network(), unixAddr)
	if err != nil {
		return nil, fmt.Errorf("create UDS listener: %w", err)
	}

	if err := os.Chmod(e.addr.String(), os.ModePerm); err != nil {
		return nil, fmt.Errorf("unable to change UDS permissions: %w", err)
	}
	return l, nil
}

func (e *Endpoints) createListener() (net.Listener, error) {
	switch e.addr.Network() {
	case "unix":
		return e.createUDSListener()
	case "pipe":
		return nil, peertracker.ErrUnsupportedPlatform
	default:
		return nil, net.UnknownNetworkError(e.addr.Network())
	}
}
