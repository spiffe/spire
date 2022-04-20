//go:build !windows
// +build !windows

package endpoints

import (
	"fmt"
	"net"

	"github.com/spiffe/spire/pkg/common/peertracker"
)

func (e *Endpoints) listenWithAuditLog() (*peertracker.Listener, error) {
	unixListener := &peertracker.ListenerFactory{
		Log: e.Log,
	}
	unixAddr, ok := e.LocalAddr.(*net.UnixAddr)
	if !ok {
		return nil, fmt.Errorf("create UDS listener: address is type %T, not net.UnixAddr", e.LocalAddr)
	}
	return unixListener.ListenUnix(e.LocalAddr.Network(), unixAddr)
}
