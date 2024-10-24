package util

import (
	"fmt"
	"net"
	"path/filepath"
)

// GetUnixAddr returns a unix address with the designated
// path. Path is converted to an absolute path when constructing
// the returned unix domain socket address.
func GetUnixAddrWithAbsPath(path string) (*net.UnixAddr, error) {
	pathAbs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path for socket path: %w", err)
	}

	return &net.UnixAddr{
		Name: pathAbs,
		Net:  "unix",
	}, nil
}

func GetUnixAddr(name string) *net.UnixAddr {
	return &net.UnixAddr{
		Name: name,
		Net:  "unix",
	}
}

// GetTargetName gets the fully qualified, self-contained name used
// for gRPC channel construction. Supported networks are unix and tcp.
// Unix paths must be absolute.
func GetTargetName(addr net.Addr) (string, error) {
	switch addr.Network() {
	case "unix":
		return "unix://" + addr.String(), nil
	case "pipe":
		return addr.String(), nil
	default:
		return "", fmt.Errorf("unsupported network %q", addr.Network())
	}
}
