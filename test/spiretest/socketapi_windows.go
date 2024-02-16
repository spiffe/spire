//go:build windows

package spiretest

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"path/filepath"
	"testing"

	"github.com/Microsoft/go-winio"
	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/spiffe/spire/pkg/common/namedpipe"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

func StartWorkloadAPI(t *testing.T, server workload.SpiffeWorkloadAPIServer) net.Addr {
	return StartWorkloadAPIOnNamedPipe(t, namedpipe.GetPipeName(GetRandNamedPipeAddr().String()), server)
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
	return namedpipe.AddrFromName(namedpipe.GetPipeName(listener.Addr().String()))
}

func ServeGRPCServerOnRandPipeName(t *testing.T, server *grpc.Server) net.Addr {
	return ServeGRPCServerOnNamedPipe(t, server, GetRandNamedPipeAddr().String())
}

func GetRandNamedPipeAddr() net.Addr {
	return namedpipe.AddrFromName(fmt.Sprintf("spire-test-%x", randUint64()))
}

func randUint64() uint64 {
	var value uint64
	if err := binary.Read(rand.Reader, binary.LittleEndian, &value); err != nil {
		panic(fmt.Sprintf("failed to generate random value for pipe name: %v", err))
	}
	return value
}
