//go:build !windows

package broker

import (
	"fmt"
	"net"
	"os"

	"github.com/spiffe/spire/pkg/common/util"
)

func createUDSListener(bindAddr net.Addr) (net.Listener, error) {
	if bindAddr.Network() != "unix" {
		return nil, fmt.Errorf("unsupported network type %q for UDS listener", bindAddr.Network())
	}

	// Remove uds if already exists
	os.Remove(bindAddr.String())

	l, err := net.ListenUnix(bindAddr.Network(), util.GetUnixAddr(bindAddr.String()))
	if err != nil {
		return nil, fmt.Errorf("error creating UDS listener: %w", err)
	}
	if err := os.Chmod(bindAddr.String(), 0770); err != nil {
		return nil, fmt.Errorf("unable to change UDS permissions: %w", err)
	}
	return l, nil
}
