//go:build windows
// +build windows

package util

import (
	"context"
	"net"

	"github.com/Microsoft/go-winio"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type pipeAddr struct {
	path    string
	network string
}

func (p *pipeAddr) Network() string {
	return p.network
}

func (p *pipeAddr) String() string {
	return p.path
}

// GetNamedPipeAddr returns a named pipe address with the
// specified path
func GetNamedPipeAddr(path string) (net.Addr, error) {
	return &pipeAddr{
		network: "pipe",
		path:    path,
	}, nil
}

func GRPCDialContext(ctx context.Context, target string) (*grpc.ClientConn, error) {
	return grpc.DialContext(ctx, target, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(winio.DialPipeContext))
}
