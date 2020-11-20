package spiretest

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/spiffe/spire/proto/spire/api/registration"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

func StartRegistrationAPIOnTempSocket(t *testing.T, server registration.RegistrationServer) string {
	dir := TempDir(t)
	socketPath := filepath.Join(dir, "registration.sock")

	StartRegistrationAPIOnSocket(t, socketPath, server)

	return socketPath
}

func StartRegistrationAPIOnSocket(t *testing.T, socketPath string, server registration.RegistrationServer) {
	StartGRPCSocketServer(t, socketPath, func(s *grpc.Server) {
		registration.RegisterRegistrationServer(s, server)
	})
}

func StartWorkloadAPIOnTempSocket(t *testing.T, server workload.SpiffeWorkloadAPIServer) string {
	dir := TempDir(t)
	socketPath := filepath.Join(dir, "workload.sock")

	StartWorkloadAPIOnSocket(t, socketPath, server)

	return socketPath
}

func StartWorkloadAPIOnSocket(t *testing.T, socketPath string, server workload.SpiffeWorkloadAPIServer) {
	StartGRPCSocketServer(t, socketPath, func(s *grpc.Server) {
		workload.RegisterSpiffeWorkloadAPIServer(s, server)
	})
}

func StartGRPCSocketServerOnTempSocket(t *testing.T, registerFn func(s *grpc.Server)) string {
	dir := TempDir(t)
	socketPath := filepath.Join(dir, "server.sock")
	StartGRPCSocketServer(t, socketPath, registerFn)
	return socketPath
}

func StartGRPCSocketServer(t *testing.T, socketPath string, registerFn func(s *grpc.Server)) {
	server := grpc.NewServer()
	registerFn(server)

	ServeGRPCServerOnSocket(t, server, socketPath)
}

func ServeGRPCServerOnTempSocket(t *testing.T, server *grpc.Server) string {
	dir := TempDir(t)
	socketPath := filepath.Join(dir, "server.sock")
	ServeGRPCServerOnSocket(t, server, socketPath)
	return socketPath
}

func ServeGRPCServerOnSocket(t *testing.T, server *grpc.Server, socketPath string) {
	// ensure the directory holding the socket exists
	require.NoError(t, os.MkdirAll(filepath.Dir(socketPath), 0755))

	listener, err := net.Listen("unix", socketPath)
	require.NoError(t, err)
	ServeGRPCServerOnListener(t, server, listener)
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
		case err == nil, err == grpc.ErrServerStopped:
		default:
			t.Fatal(err)
		}
	})
}
