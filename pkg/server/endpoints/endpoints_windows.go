//go:build windows
// +build windows

package endpoints

import (
	"net"

	"github.com/Microsoft/go-winio"
	"github.com/spiffe/spire/pkg/common/peertracker"
	"github.com/spiffe/spire/pkg/common/util"
)

func (e *Endpoints) listen() (net.Listener, error) {
	return winio.ListenPipe(e.LocalAddr.String(), &winio.PipeConfig{SecurityDescriptor: util.SDDLPrivateListener})
}

func (e *Endpoints) listenWithAuditLog() (*peertracker.Listener, error) {
	lf := &peertracker.ListenerFactory{
		Log: e.Log,
	}

	return lf.ListenPipe(e.LocalAddr.String(), &winio.PipeConfig{SecurityDescriptor: util.SDDLPrivateListener})
}

func (e *Endpoints) restrictLocalAddr() error {
	// Access control is already handled by the security
	// descriptor associated with the named pipe.
	// Nothing else is needed to be done here.
	return nil
}
