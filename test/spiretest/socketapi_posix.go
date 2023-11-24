//go:build !windows

package spiretest

import (
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
