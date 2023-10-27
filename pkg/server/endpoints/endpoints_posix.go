//go:build !windows

package endpoints

import (
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/spiffe/spire/pkg/common/peertracker"
)

func (e *Endpoints) listen() (net.Listener, error) {
	return net.Listen(e.LocalAddr.Network(), e.LocalAddr.String())
}

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

func (e *Endpoints) restrictLocalAddr() error {
	// Restrict access to the UDS to processes running as the same user or
	// group as the server.
	return os.Chmod(e.LocalAddr.String(), 0770)
}

func prepareLocalAddr(localAddr net.Addr) error {
	if err := os.MkdirAll(filepath.Dir(localAddr.String()), 0750); err != nil {
		return fmt.Errorf("unable to create socket directory: %w", err)
	}

	return nil
}
