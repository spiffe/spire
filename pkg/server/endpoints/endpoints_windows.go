//go:build windows
// +build windows

package endpoints

import (
	"errors"

	"github.com/spiffe/spire/pkg/common/peertracker"
)

func (e *Endpoints) listenWithAuditLog() (*peertracker.Listener, error) {
	return nil, errors.New("audit log is not supported in this platform")
}
