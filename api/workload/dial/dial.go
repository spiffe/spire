package dial

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc"
)

// Dial calls the SPIFFE Workload Endpoint and returns a connection to it. If `addr` is
// not set, it will pull from the SPIFFE_ENDPOINT_SOCKET environment variable.
func Dial(ctx context.Context, addr net.Addr) (*grpc.ClientConn, error) {
	var err error
	if addr == nil {
		addr, err = addrFromEnv()
	}
	if err != nil {
		return nil, err
	}

	// Workload API is unauthenticated
	d := dialer(addr.Network())
	return grpc.DialContext(ctx, addr.String(), grpc.WithInsecure(), grpc.WithDialer(d)) //nolint: staticcheck
}

func addrFromEnv() (net.Addr, error) {
	val, ok := os.LookupEnv("SPIFFE_ENDPOINT_SOCKET")
	if !ok {
		return nil, errors.New("socket address not configured")
	}

	u, err := url.Parse(val)
	if err != nil {
		return nil, fmt.Errorf("parse address from env: %v", err)
	}

	switch u.Scheme {
	case "tcp":
		return parseTCPAddr(u)
	case "unix":
		return parseUDSAddr(u)
	default:
		return nil, fmt.Errorf("unsupported network type: %v", u.Scheme)
	}
}

func parseTCPAddr(u *url.URL) (net.Addr, error) {
	parts := strings.Split(u.Host, ":")
	if len(parts) != 2 {
		return nil, fmt.Errorf("address must be defined as ip:port; got: %v", u.Host)
	}

	ip := net.ParseIP(parts[0])
	if ip == nil {
		return nil, fmt.Errorf("tcp address is not an IP: %v", parts[0])
	}

	port, err := strconv.Atoi(parts[1])
	if err != nil {
		return nil, fmt.Errorf("tcp port is not an integer: %v", err)
	}

	addr := &net.TCPAddr{
		IP:   ip,
		Port: port,
	}

	return addr, nil
}

func parseUDSAddr(u *url.URL) (net.Addr, error) {
	if u.Host != "" {
		return nil, fmt.Errorf("unexpected authority component in unix uri: %v", u.Host)
	}

	if u.Path == "" {
		return nil, errors.New("no path defined for unix uri")
	}

	if u.Path[0] != '/' {
		return nil, fmt.Errorf("unix socket path not absolute: %v", u.Path)
	}

	addr := &net.UnixAddr{
		Net:  "unix",
		Name: u.Path,
	}

	return addr, nil
}

func dialer(network string) func(addr string, timeout time.Duration) (net.Conn, error) {
	return func(addr string, timeout time.Duration) (net.Conn, error) {
		return net.DialTimeout(network, addr, timeout)
	}
}
