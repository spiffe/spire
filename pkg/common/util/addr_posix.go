//go:build !windows
// +build !windows

package util

import (
	"context"
	"errors"
	"net"

	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func GRPCDialContext(ctx context.Context, target string) (*grpc.ClientConn, error) {
	return grpc.DialContext(ctx, target, grpc.WithTransportCredentials(insecure.NewCredentials()))
}

func GetWorkloadAPIClientOptions(addr net.Addr) ([]workloadapi.ClientOption, error) {
	if _, ok := addr.(*net.UnixAddr); !ok {
		return nil, errors.New("address does not represent a Unix domain socket endpoint")
	}
	target, err := GetTargetName(addr)
	if err != nil {
		return nil, err
	}
	return []workloadapi.ClientOption{workloadapi.WithAddr(target)}, nil
}
