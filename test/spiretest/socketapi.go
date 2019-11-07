package spiretest

import (
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/spiffe/go-spiffe/proto/spiffe/workload"
	"github.com/spiffe/spire/proto/spire/api/registration"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

func StartRegistrationAPIOnTempSocket(t *testing.T, server registration.RegistrationServer) (string, func()) {
	dir, err := ioutil.TempDir("", "")
	require.NoError(t, err)
	socketPath := filepath.Join(dir, "registration.sock")

	ok := false
	defer func() {
		if !ok {
			os.RemoveAll(dir)
		}
	}()

	closeServer := StartRegistrationAPIOnSocket(t, socketPath, server)

	ok = true
	return socketPath, func() {
		closeServer()
		os.RemoveAll(dir)
	}
}

func StartRegistrationAPIOnSocket(t *testing.T, socketPath string, server registration.RegistrationServer) func() {
	return StartGRPCSocketServer(t, socketPath, func(s *grpc.Server) {
		registration.RegisterRegistrationServer(s, server)
	})
}

func StartWorkloadAPIOnTempSocket(t *testing.T, server workload.SpiffeWorkloadAPIServer) (string, func()) {
	dir, err := ioutil.TempDir("", "")
	require.NoError(t, err)
	socketPath := filepath.Join(dir, "workload.sock")

	ok := false
	defer func() {
		if !ok {
			os.RemoveAll(dir)
		}
	}()

	closeServer := StartWorkloadAPIOnSocket(t, socketPath, server)

	ok = true
	return socketPath, func() {
		closeServer()
		os.RemoveAll(dir)
	}
}

func StartWorkloadAPIOnSocket(t *testing.T, socketPath string, server workload.SpiffeWorkloadAPIServer) func() {
	return StartGRPCSocketServer(t, socketPath, func(s *grpc.Server) {
		workload.RegisterSpiffeWorkloadAPIServer(s, server)
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

	serverDone := make(chan error, 1)
	go func() {
		serverDone <- server.Serve(listener)
	}()
	started = true
	return func() {
		server.Stop()
		require.NoError(t, <-serverDone)
	}
}
