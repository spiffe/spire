//go:build windows
// +build windows

package api

import (
	"net"

	"github.com/spiffe/spire/pkg/common/peertracker"
)

func (e *Endpoints) createListener() (net.Listener, error) {
	return nil, peertracker.ErrUnsupportedPlatform
}
