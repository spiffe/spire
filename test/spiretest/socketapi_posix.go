//go:build !windows

package spiretest

import (
	"errors"
	"net"
	"path/filepath"
	"testing"

	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"google.golang.org/grpc"
)

func StartWorkloadAPI(t *testing.T, server workload.SpiffeWorkloadAPIServer) net.Addr {
	dir := TempDir(t)
	socketPath := filepath.Join(dir, "workload.sock")

	return StartWorkloadAPIOnUDSSocket(t, socketPath, server)
}

func StartGRPCServer(t *testing.T, registerFn func(s *grpc.Server)) net.Addr {
	dir := TempDir(t)
	socketPath := filepath.Join(dir, "server.sock")
	return StartGRPCUDSSocketServer(t, socketPath, registerFn)
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
