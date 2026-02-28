//go:build windows

package broker

import (
	"fmt"
	"net"
)

func createUDSListener(_ net.Addr) (net.Listener, error) {
	return nil, fmt.Errorf("unsupported platform for broker API")
}
