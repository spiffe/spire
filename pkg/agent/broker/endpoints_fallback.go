//go:build windows

package broker

import (
	"errors"
	"net"
)

func createUDSListener(_ net.Addr) (net.Listener, error) {
	return nil, errors.New("unsupported platform for broker API")
}
