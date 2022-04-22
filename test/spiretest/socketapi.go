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

func StartWorkloadAPIOnUDSSocket(t *testing.T, socketPath string, server workload.SpiffeWorkloadAPIServer) net.Addr {
	return StartGRPCUDSSocketServer(t, socketPath, func(s *grpc.Server) {
		workload.RegisterSpiffeWorkloadAPIServer(s, server)
	})
}

func StartGRPCUDSSocketServer(t *testing.T, socketPath string, registerFn func(s *grpc.Server)) net.Addr {
	server := grpc.NewServer()
	registerFn(server)

	return ServeGRPCServerOnUDSSocket(t, server, socketPath)
}

func ServeGRPCServerOnTempUDSSocket(t *testing.T, server *grpc.Server) net.Addr {
	dir := TempDir(t)
	socketPath := filepath.Join(dir, "server.sock")
	return ServeGRPCServerOnUDSSocket(t, server, socketPath)
}

func ServeGRPCServerOnUDSSocket(t *testing.T, server *grpc.Server, socketPath string) net.Addr {
	// ensure the directory holding the socket exists
	require.NoError(t, os.MkdirAll(filepath.Dir(socketPath), 0755))

	listener, err := net.Listen("unix", socketPath)
	require.NoError(t, err)
	ServeGRPCServerOnListener(t, server, listener)
	return listener.Addr()
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
