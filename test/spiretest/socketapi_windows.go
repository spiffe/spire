//go:build windows
// +build windows

package spiretest

import (
	"fmt"
	"math/rand"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/Microsoft/go-winio"
	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

func StartWorkloadAPI(t *testing.T, server workload.SpiffeWorkloadAPIServer) net.Addr {
	return StartWorkloadAPIOnNamedPipe(t, util.GetPipeName(GetRandNamedPipeAddr().String()), server)
}

func StartWorkloadAPIOnNamedPipe(t *testing.T, pipeName string, server workload.SpiffeWorkloadAPIServer) net.Addr {
	return StartGRPCOnNamedPipeServer(t, pipeName, func(s *grpc.Server) {
		workload.RegisterSpiffeWorkloadAPIServer(s, server)
	})
}

func StartGRPCServer(t *testing.T, registerFn func(s *grpc.Server)) net.Addr {
	return StartGRPCOnNamedPipeServer(t, GetRandNamedPipeAddr().String(), registerFn)
}

func StartGRPCOnNamedPipeServer(t *testing.T, pipeName string, registerFn func(s *grpc.Server)) net.Addr {
	server := grpc.NewServer()
	registerFn(server)

	return ServeGRPCServerOnNamedPipe(t, server, pipeName)
}

func ServeGRPCServerOnNamedPipe(t *testing.T, server *grpc.Server, pipeName string) net.Addr {
	listener, err := winio.ListenPipe(fmt.Sprintf(`\\.\`+filepath.Join("pipe", pipeName)), nil)
	require.NoError(t, err)
	ServeGRPCServerOnListener(t, server, listener)
	return util.GetNamedPipeAddr(util.GetPipeName(listener.Addr().String()))
}

func ServeGRPCServerOnRandPipeName(t *testing.T, server *grpc.Server) net.Addr {
	return ServeGRPCServerOnNamedPipe(t, server, GetRandNamedPipeAddr().String())
}

func GetRandNamedPipeAddr() net.Addr {
	return util.GetNamedPipeAddr(fmt.Sprintf("spire-test-%x", rand.Uint64())) // nolint: gosec // used for testing only
}

func init() {
	rand.Seed(time.Now().UnixNano())
}
