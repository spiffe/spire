//go:build windows
// +build windows

package util

import (
	"context"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strings"

	"github.com/Microsoft/go-winio"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type NamedPipeAddr struct {
	serverName string
	pipeName   string
}

func (p *NamedPipeAddr) PipeName() string {
	return p.pipeName
}

func (p *NamedPipeAddr) Network() string {
	return "pipe"
}

func (p *NamedPipeAddr) String() string {
	return fmt.Sprintf(`\\%s\%s`, p.serverName, filepath.Join("pipe", p.pipeName))
}

// GetNamedPipeAddr returns a named pipe in the local
// computer with the specified pipe name
func GetNamedPipeAddr(pipeName string) net.Addr {
	return &NamedPipeAddr{
		serverName: ".",
		pipeName:   pipeName,
	}
}

func GRPCDialContext(ctx context.Context, target string) (*grpc.ClientConn, error) {
	return grpc.DialContext(ctx, target, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(winio.DialPipeContext))
}

func GetWorkloadAPIClientOptions(addr net.Addr) ([]workloadapi.ClientOption, error) {
	if _, ok := addr.(*NamedPipeAddr); !ok {
		return nil, errors.New("address is not a named pipe address")
	}
	return []workloadapi.ClientOption{workloadapi.WithNamedPipeName(addr.(*NamedPipeAddr).PipeName())}, nil
}

func GetPipeName(addr string) string {
	return strings.TrimPrefix(addr, `\\.\pipe`)
}
