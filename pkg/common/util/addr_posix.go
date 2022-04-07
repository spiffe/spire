//go:build !windows
// +build !windows

package util

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func GRPCDialContext(ctx context.Context, target string) (*grpc.ClientConn, error) {
	return grpc.DialContext(ctx, target, grpc.WithTransportCredentials(insecure.NewCredentials()))
}
