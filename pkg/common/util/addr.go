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

func GetLocalTCPAddr(tcpSocketPort int) *net.TCPAddr {
	return &net.TCPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: tcpSocketPort,
	}
}

// GetTargetName gets the fully qualified, self contained name used
// for gRPC channel construction. Supported networks are unix and tcp.
// Unix paths must be absolute.
func GetTargetName(addr net.Addr) (string, error) {
	switch addr.Network() {
	case "unix":
		return "unix://" + addr.String(), nil
	case "tcp", "pipe":
		return addr.String(), nil
	default:
		return "", fmt.Errorf("unsupported network %q", addr.Network())
	}
}

// GetURIAddress gets the specified address structured as an URI.
// The returned address is a valid SPIFFE Workload API Endpoint
// address according with the specification:
// https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Workload_Endpoint.md
func GetURIAddress(addr net.Addr) (string, error) {
	switch addr.Network() {
	case "unix":
		pathAbs, err := filepath.Abs(addr.String())
		if err != nil {
			return "", fmt.Errorf("failed to get absolute path for socket path: %w", err)
		}
		return "unix://" + pathAbs, nil
	case "tcp":
		return "tcp://" + addr.String(), nil
	case "pipe":
		return addr.String(), nil
	default:
		return "", fmt.Errorf("unsupported network %q", addr.Network())
	}
}
