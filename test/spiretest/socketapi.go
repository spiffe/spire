package spiretest

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

func StartWorkloadAPIOnTempUDSSocket(t *testing.T, server workload.SpiffeWorkloadAPIServer) *net.UnixAddr {
	dir := TempDir(t)
	socketPath := filepath.Join(dir, "workload.sock")

	return StartWorkloadAPIOnUDSSocket(t, socketPath, server)
}

func StartWorkloadAPIOnFreeTCPSocket(t *testing.T, server workload.SpiffeWorkloadAPIServer) *net.TCPAddr {
	return StartWorkloadAPIOnTCPSocket(t, 0, server)
}

func StartWorkloadAPIOnUDSSocket(t *testing.T, socketPath string, server workload.SpiffeWorkloadAPIServer) *net.UnixAddr {
	return StartGRPCUDSSocketServer(t, socketPath, func(s *grpc.Server) {
		workload.RegisterSpiffeWorkloadAPIServer(s, server)
	})
}

func StartWorkloadAPIOnTCPSocket(t *testing.T, tcpSocketPort int, server workload.SpiffeWorkloadAPIServer) *net.TCPAddr {
	return StartGRPCTCPSocketServer(t, 0, func(s *grpc.Server) {
		workload.RegisterSpiffeWorkloadAPIServer(s, server)
	})
}

func StartGRPCSocketServerOnTempUDSSocket(t *testing.T, registerFn func(s *grpc.Server)) string {
	dir := TempDir(t)
	socketPath := filepath.Join(dir, "server.sock")
	StartGRPCUDSSocketServer(t, socketPath, registerFn)
	return socketPath
}

func StartGRPCSocketServerOnFreeTCPSocket(t *testing.T, registerFn func(s *grpc.Server)) *net.TCPAddr {
	return StartGRPCTCPSocketServer(t, 0, registerFn)
}

func StartGRPCUDSSocketServer(t *testing.T, socketPath string, registerFn func(s *grpc.Server)) *net.UnixAddr {
	server := grpc.NewServer()
	registerFn(server)

	return ServeGRPCServerOnUDSSocket(t, server, socketPath)
}

func StartGRPCTCPSocketServer(t *testing.T, tcpSocketPort int, registerFn func(s *grpc.Server)) *net.TCPAddr {
	server := grpc.NewServer()
	registerFn(server)

	return ServeGRPCServerOnTCPSocket(t, server, tcpSocketPort)
}

func ServeGRPCServerOnTempUDSSocket(t *testing.T, server *grpc.Server) string {
	dir := TempDir(t)
	socketPath := filepath.Join(dir, "server.sock")
	ServeGRPCServerOnUDSSocket(t, server, socketPath)
	return socketPath
}

func ServeGRPCServerOnFreeTCPSocket(t *testing.T, server *grpc.Server) *net.TCPAddr {
	return ServeGRPCServerOnTCPSocket(t, server, 0)
}

func ServeGRPCServerOnUDSSocket(t *testing.T, server *grpc.Server, socketPath string) *net.UnixAddr {
	// ensure the directory holding the socket exists
	require.NoError(t, os.MkdirAll(filepath.Dir(socketPath), 0755))

	listener, err := net.Listen("unix", socketPath)
	require.NoError(t, err)
	ServeGRPCServerOnListener(t, server, listener)
	return listener.Addr().(*net.UnixAddr)
}

func ServeGRPCServerOnTCPSocket(t *testing.T, server *grpc.Server, tcpSocketPort int) *net.TCPAddr {
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", tcpSocketPort))
	require.NoError(t, err)
	ServeGRPCServerOnListener(t, server, listener)
	return listener.Addr().(*net.TCPAddr)
}

func ServeGRPCServerOnListener(t *testing.T, server *grpc.Server, listener net.Listener) {
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Serve(listener)
	}()
	t.Cleanup(func() {
		server.Stop()
		err := <-errCh
		switch {
		case err == nil, errors.Is(err, grpc.ErrServerStopped):
		default:
			t.Fatal(err)
		}
	})
}
