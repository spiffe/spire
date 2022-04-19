//go:build !windows
// +build !windows

package spiretest

import (
	"net"
	"path/filepath"
	"testing"

	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
)

func StartWorkloadAPI(t *testing.T, server workload.SpiffeWorkloadAPIServer) net.Addr {
	dir := TempDir(t)
	socketPath := filepath.Join(dir, "workload.sock")

	return StartWorkloadAPIOnUDSSocket(t, socketPath, server)
}
