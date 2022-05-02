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

const (
	// SDDLPrivateListener describes a security descriptor using the
	// security descriptor definition language (SDDL) that is meant
	// to be used to define the access control to named pipes
	// listeners that only need to be accessed locally by the owner
	// of the service, granting read, write and execute permissions
	// to the creator owner only.
	// E.g.: SPIRE Server APIs, Admin APIs.
	SDDLPrivateListener = "D:P(A;;GRGWGX;;;OW)"

	// SDDLPublicListener describes a security descriptor using the
	// security descriptor definition language (SDDL) that is meant
	// to be used to define the access control to named pipes
	// listeners that need to be publicly accessed, granting read,
	// write and execute permissions to everyone.
	// E.g.: SPIFFE Workload API.
	SDDLPublicListener = "D:P(A;;GRGWGX;;;WD)"
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

func GRPCDialContext(ctx context.Context, target string, options ...grpc.DialOption) (*grpc.ClientConn, error) {
	options = append(options, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(winio.DialPipeContext))
	return grpc.DialContext(ctx, target, options...)
}

func GetWorkloadAPIClientOption(addr net.Addr) (workloadapi.ClientOption, error) {
	if _, ok := addr.(*NamedPipeAddr); !ok {
		return nil, errors.New("address is not a named pipe address")
	}
	return workloadapi.WithNamedPipeName(addr.(*NamedPipeAddr).PipeName()), nil
}

func GetPipeName(addr string) string {
	return strings.TrimPrefix(addr, `\\.\pipe`)
}
