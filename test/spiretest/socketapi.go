package spiretest

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

func StartWorkloadAPIOnUDSSocket(t *testing.T, socketPath string, server workload.SpiffeWorkloadAPIServer) *net.UnixAddr {
	return StartGRPCUDSSocketServer(t, socketPath, func(s *grpc.Server) {
		workload.RegisterSpiffeWorkloadAPIServer(s, server)
	})
}

func StartGRPCSocketServerOnTempUDSSocket(t *testing.T, registerFn func(s *grpc.Server)) string {
	dir := TempDir(t)
	socketPath := filepath.Join(dir, "server.sock")
	StartGRPCUDSSocketServer(t, socketPath, registerFn)
	return socketPath
}

func StartGRPCUDSSocketServer(t *testing.T, socketPath string, registerFn func(s *grpc.Server)) *net.UnixAddr {
	server := grpc.NewServer()
	registerFn(server)

	return ServeGRPCServerOnUDSSocket(t, server, socketPath)
}

func ServeGRPCServerOnTempUDSSocket(t *testing.T, server *grpc.Server) string {
	dir := TempDir(t)
	socketPath := filepath.Join(dir, "server.sock")
	ServeGRPCServerOnUDSSocket(t, server, socketPath)
	return socketPath
}

func ServeGRPCServerOnUDSSocket(t *testing.T, server *grpc.Server, socketPath string) *net.UnixAddr {
	// ensure the directory holding the socket exists
	require.NoError(t, os.MkdirAll(filepath.Dir(socketPath), 0755))

	listener, err := net.Listen("unix", socketPath)
	require.NoError(t, err)
	ServeGRPCServerOnListener(t, server, listener)
	return listener.Addr().(*net.UnixAddr)
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
