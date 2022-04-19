//go:build !windows
// +build !windows

package endpoints

import (
	"github.com/spiffe/spire/pkg/common/peertracker"
)

func (e *Endpoints) listenWithAuditLog() (*peertracker.Listener, error) {
	unixListener := &peertracker.ListenerFactory{
		Log: e.Log,
	}
	return unixListener.ListenUnix(e.UDSAddr.Network(), e.UDSAddr)
}
