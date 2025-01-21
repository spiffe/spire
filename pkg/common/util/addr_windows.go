//go:build windows

package util

import (
	"errors"
	"net"

	"github.com/Microsoft/go-winio"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/spiffe/spire/pkg/common/namedpipe"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func NewGRPCClient(target string, options ...grpc.DialOption) (*grpc.ClientConn, error) {
	options = append(options, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(winio.DialPipeContext))
	return grpc.NewClient(target, options...)
}

func GetWorkloadAPIClientOption(addr net.Addr) (workloadapi.ClientOption, error) {
	if _, ok := addr.(*namedpipe.Addr); !ok {
		return nil, errors.New("address is not a named pipe address")
	}
	return workloadapi.WithNamedPipeName(addr.(*namedpipe.Addr).PipeName()), nil
}
