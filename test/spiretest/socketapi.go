package spiretest

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/spiffe/spire/proto/spire/api/registration"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

func StartRegistrationAPIOnSocket(t *testing.T, socketPath string, server registration.RegistrationServer) func() {
	return StartGRPCSocketServer(t, socketPath, func(s *grpc.Server) {
		registration.RegisterRegistrationServer(s, server)
	})
}

func StartGRPCSocketServer(t *testing.T, socketPath string, registerFn func(s *grpc.Server)) func() {
	// ensure the directory holding the socket exists
	require.NoError(t, os.MkdirAll(filepath.Dir(socketPath), 0755))

	// start up a listener. close it unless the function finishes and the
	// gRPC server owns it.
	listener, err := net.Listen("unix", socketPath)
	require.NoError(t, err)
	started := false
	defer func() {
		if !started {
			listener.Close()
		}
	}()

	server := grpc.NewServer()
	registerFn(server)
	go server.Serve(listener)
	started = true
	return server.Stop
}
